#include "crowd_safe_gencode.h"
#include <string.h>
#include "../../core/x86/arch.h"
#include "../../core/x86/instr.h"
#include "../../core/x86/instrument.h"
#include "../../core/x86/instr_create.h"
#include "../drcontainers/drvector.h"
#include "indirect_link_observer.h"
#include "indirect_link_hashtable.h"
#include "crowd_safe_util.h"

/**** Private Fields ****/

#define HASH_BUCKET_INDEX_EXPANSION 0x3
#define TAG_PAIRING_SHIFT 0x20

#define TEMP_REGISTER1 REG_XSI
#define TLS_TEMP_REGISTER1 TLS_XSI_TEMP
#define TEMP_REGISTER2 REG_XDX
#define TLS_TEMP_REGISTER2 TLS_XDX_TEMP

#ifdef UNIX
# define BREAKPOINT "break *"PX"\n"
# define DEBUG_SCRIPT_COMMENT(comment) "# "comment
#else
# define BREAKPOINT "bp "IF_X64_ELSE("%llx","%lx")"\n"
# define BREAKPOINT_CONDITIONAL "bp "IF_X64_ELSE("%llx","%lx")" \".if @@c++(%s) {} .else {gc}\"\n"
# define DEBUG_SCRIPT_COMMENT(comment) "$$ "##comment
#endif

#ifdef UNIX
# include <unistd.h>
# define PWD getcwd
#else
# include <direct.h>
# define PWD _getcwd
#endif

#define APP(ilist, instr_expr) \
do { \
    instr_t *instr = instr_expr; \
    instrlist_meta_append(ilist, instr); \
} while(0);
//CS_TRACK(instr, sizeof(instr_t));

#define HASH_BUCKET_TO 4
#define HASH_BUCKET_HASH 0

#ifdef SEED_TLS_FOR_IBL_VERIFICATION
# define DEBUG_GENCODE 1
#endif

typedef struct _top_level_jump_targets_t {
    instr_t* shadow_stack_resolution_start;
    instr_t* shadow_stack_resolution_return;
    instr_t* indirect_link_notification_start;
    instr_t* indirect_link_notification_return;
    instr_t* ibl_found_hook;
} top_level_jump_targets_t;

static top_level_jump_targets_t *top_level_jump_targets;

static drvector_t *instrumented_ibl_routine_start_pcs;
static drvector_t *instrumented_syscall_routine_entry_points;
static bool *gencode_in_progress;

#ifdef DEBUG_GENCODE
static file_t breakpoint_file;
#endif

/**** Private Prototypes ****/

/* Called by debug code to identify the index of the IBL block having the
 * specified head PC. */
static int
get_ibl_start_pc_index(byte *ibl_start_pc);

static bool
is_tracked_ibl_routine(byte *);

static bool
is_tracked_syscall_routine(byte *pc);

static void
append_indirect_branch_pairing_routine(dcontext_t *dcontext, instrlist_t *ilist,
                                       ibl_code_t *ibl_code, instr_t *fragment_not_found);

static void
append_shadow_stack_resolution_routine(dcontext_t *dcontext, instrlist_t *ilist,
                                       ibl_code_t *ibl_code, instr_t *fragment_not_found);

/**** Public Functions ****/

/** this function goes at the top b/c it is a very common breakpoint **/
void
notify_gencode_complete() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (CROWD_SAFE_BB_GRAPH())
        *gencode_in_progress = false;
}

void
init_crowd_safe_gencode() {
#ifdef DEBUG_GENCODE
# ifdef UNIX
    const char *filename = "./gencode_breakpoints";
# else
    char filename[1024];
# endif
#endif
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    CS_LOG("Starting gencode\n");

#ifdef DEBUG_GENCODE
# ifdef WINDOWS
    if (PWD(filename, sizeof(filename)) != NULL) {
        strcat(filename, "\\gencode_breakpoints.gdx");
    }
# endif
    breakpoint_file = dr_open_file(filename, DR_FILE_WRITE_OVERWRITE);
    if (breakpoint_file == INVALID_FILE)
        CS_ERR("Failed to create the file \"gencode_breakpoints.gdx\"\n");
#endif

    instrumented_ibl_routine_start_pcs = (drvector_t*)CS_ALLOC(sizeof(drvector_t));
    drvector_init(instrumented_ibl_routine_start_pcs, 200UL, false, NULL);

    instrumented_syscall_routine_entry_points = (drvector_t*)CS_ALLOC(sizeof(drvector_t));
    drvector_init(instrumented_syscall_routine_entry_points, 200UL, false, NULL);

    top_level_jump_targets = (top_level_jump_targets_t *)CS_ALLOC(sizeof(top_level_jump_targets_t));

    // cs-todo: destroy on exit
    gencode_in_progress = (bool *)CS_ALLOC(sizeof(bool));
    *gencode_in_progress = false;
}

void
notify_gencode_starting() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    ASSERT(!*gencode_in_progress);

    top_level_jump_targets->indirect_link_notification_start = (instr_t *) PC(0);
    top_level_jump_targets->ibl_found_hook = (instr_t *) PC(0);
    *gencode_in_progress = true;
}

uint
insert_indirect_link_branchpoint(dcontext_t *dcontext, instrlist_t *bb, app_pc bb_tag,
                                 instr_t *ibl_instr, bool is_return, int syscall_number) {
    instr_t /* *save_temp1, */ *memo_branchpoint, /* *save_from_tag, *restore_temp1, */*set_flags;
    bool is_ibl = false;
    bool is_syscall = false;
    uint flags = 0UL;
    uint added_size = 0U;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, 0);

    if (!CROWD_SAFE_BB_GRAPH())
        return 0;

    if (ibl_instr->src0.kind != PC_kind) {
        if (ibl_instr->src0.kind == BASE_DISP_kind) {
            CS_WARN("Skipping instrumentation of branch to ibl with base+disp operand 0\n", ibl_instr->src0.kind);
        } else {
            CS_WARN("Skipping instrumentation of branch to ibl with operand 0 of kind %d\n", ibl_instr->src0.kind);
        }
        return 0;
    }

    if (!*gencode_in_progress) {
        if (ibl_instr->src0.value.pc == get_shared_gencode(dcontext _IF_X64(GENCODE_FROM_DCONTEXT))->do_syscall)
            CS_WARN("Linking BB to do_syscall!\n");
#ifdef UNIX  // CS-TODO: what for WINDOWS?
        if (ibl_instr->src0.value.pc == get_shared_gencode(dcontext _IF_X64(GENCODE_FROM_DCONTEXT))->do_int_syscall)
            CS_WARN("Linking BB to do_int_syscall!\n");
#endif
        if (ibl_instr->src0.value.pc == get_shared_gencode(dcontext _IF_X64(GENCODE_FROM_DCONTEXT))->fcache_return)
            CS_WARN("Linking BB to fcache_return!\n");
    }

    if (is_tracked_ibl_routine(ibl_instr->src0.value.pc)) {
        is_ibl = true;
    } else if (is_tracked_syscall_routine(ibl_instr->src0.value.pc)) {
        is_syscall = true;
    }
    if (!(is_ibl || is_syscall))
        return 0;

    // make sure the OS pads the high bytes with 0
    // ASSERT((p2int(bb_tag) & 0xF000000000000000ULL) == 0);

    // Set the high bit of %temp1: {0=is_return, 1=!is_return}
    if (is_return) {
        flags = flags & ~IBP_META_RETURN;
        flags = flags | IBP_META_STACK_PENDING;

        CS_DET("<ret> instrumenting IBL return in "PX"\n", bb_tag);
    } else {
        flags = flags | IBP_META_RETURN;
    }
    set_flags = IMM_TO_TLS(dcontext, flags, TLS_IBP_FLAGS);
    instrlist_meta_preinsert(bb, ibl_instr, set_flags);
    added_size += instr_length(dcontext, set_flags);

    // cs-todo: this value may be multiply live across nested callbacks :-(
    // is this where the unexpected returns are coming from? Would see:
    // A -> B, B -> C, C -> B, C! -> A (should be B -> A)

    if (is_syscall && IS_CONTEXT_SWITCH(syscall_number)) {
        memo_branchpoint = IMM_TO_TLS(dcontext, 0, TLS_IBP_FROM_TAG);
        instrlist_meta_preinsert(bb, ibl_instr, memo_branchpoint);
        added_size += instr_length(dcontext, memo_branchpoint);
#ifdef X64
        memo_branchpoint = IMM_TO_TLS(dcontext, 0, TLS_IBP_FROM_TAG_HIGH);
        instrlist_meta_preinsert(bb, ibl_instr, memo_branchpoint);
        added_size += instr_length(dcontext, memo_branchpoint);
#endif
    } else {
        memo_branchpoint = IMM_TO_TLS(dcontext, MASK_LOW(VALUE_OR_SEED(bb_tag)), TLS_IBP_FROM_TAG);
        instrlist_meta_preinsert(bb, ibl_instr, memo_branchpoint);
        added_size += instr_length(dcontext, memo_branchpoint);
#ifdef X64
        memo_branchpoint = IMM_TO_TLS(dcontext, MASK_HIGH(VALUE_OR_SEED(bb_tag)), TLS_IBP_FROM_TAG_HIGH);
        instrlist_meta_preinsert(bb, ibl_instr, memo_branchpoint);
        added_size += instr_length(dcontext, memo_branchpoint);
#endif
    }

    return added_size;
}

/* Check whether `instr` is an IMM_TO_TLS of insert_indirect_link_branchpoint() */
bool
is_ibl_setup_instr(instr_t *instr)
{
    if (instr->opcode == OP_mov_st) {
        opnd_t dst = instr_get_dst(instr, 0);
        return (opnd_is_base_disp(dst) &&
                (opnd_get_disp(dst) == os_tls_offset(TLS_IBP_FLAGS) ||
                opnd_get_disp(dst) == os_tls_offset(TLS_IBP_FROM_TAG)));
    }
    return false;
}

void
prepare_fcache_return_from_ibl(dcontext_t *dcontext, instrlist_t *bb, ibl_code_t *ibl_routine_start_pc) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    if (is_tracked_ibl_routine(ibl_routine_start_pc->indirect_branch_lookup_routine)) {
        APP(bb, SAVE_TO_TLS(dcontext,
            REG_XBX,
            TLS_IBP_TO_TAG));

        // toggle the 'path pending' bit
        APP(bb, INSTR_CREATE_or(dcontext,
            OPND_TLS_FIELD(TLS_IBP_FLAGS),
            OPND_CREATE_INT32(IBP_META_PATH_PENDING)));
    }
}

void
append_indirect_link_notification_hook(dcontext_t *dcontext, instrlist_t *ilist, byte *ibl_routine_start_pc) {
    instr_t *restore_temp1, *shadow_stack_resolution_jump, *indirect_link_notification_jump;
    extern bool verify_shadow_stack;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    ASSERT(*gencode_in_progress);

    /********** branch targets ***********/

    // { %rbx=to, %temp1=from } : hashing into %temp1: shift the from tag by one bit
    top_level_jump_targets->indirect_link_notification_start = INSTR_CREATE_rol(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        OPND_CREATE_INT8(1));

    if (false && verify_shadow_stack) {

        // { %rbx=to } : restore app contents of %temp2 (though seems like I didn't use it yet)
        top_level_jump_targets->shadow_stack_resolution_start = RESTORE_FROM_TLS(dcontext,
            TEMP_REGISTER2,
            TLS_TEMP_REGISTER2);

    } else {

        // { %rbx=to } : load %ssp into %temp2
        top_level_jump_targets->shadow_stack_resolution_start = RESTORE_FROM_TLS(dcontext,
            TEMP_REGISTER2,
            TLS_SHADOW_STACK_POINTER);

    }

    // { %rbx=to }
    shadow_stack_resolution_jump = INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(top_level_jump_targets->shadow_stack_resolution_start));

    // { %rbx=to }
    restore_temp1 = RESTORE_FROM_TLS(dcontext,
        TEMP_REGISTER1,
        TLS_TEMP_REGISTER1);

    // { %rbx=to, %temp1=from }
    indirect_link_notification_jump = INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(top_level_jump_targets->indirect_link_notification_start));

    // { %rbx=to } : save app contents of %temp2
    top_level_jump_targets->ibl_found_hook = SAVE_TO_TLS(dcontext,
        TEMP_REGISTER2,
        TLS_TEMP_REGISTER2);

    /********** instruction sequence ***********/

    // { %rbx=to }
    APP(ilist, top_level_jump_targets->ibl_found_hook);

    // { %rbx=to } : save app contents of %temp1
    APP(ilist, SAVE_TO_TLS(dcontext,
        TEMP_REGISTER1,
        TLS_TEMP_REGISTER1));

    // { %rbx=to } : pull `from` tag into %temp1
    APP(ilist, RESTORE_FROM_TLS(dcontext,
        TEMP_REGISTER1,
        TLS_IBP_FROM_TAG));

    // { %rbx=to, %temp1=from } : check for `from` address of 0
    APP(ilist, INSTR_CREATE_test(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        opnd_create_reg(TEMP_REGISTER1)));

    /* { %rbx=to, %temp1=from } : %temp1 is 0, so it's a context switch, or post-syscall
                                  continuation pc lookup, and we skip all CS processing */
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jz,
        opnd_create_instr(restore_temp1)));

    // { %rbx=to, %temp1=from } : check the IBP 'return' flag
    APP(ilist, INSTR_CREATE_test(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_RETURN)));

    // { %rbx=to, %temp1=from } : `return=1` so not a return: skip shadow stack resolution
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jnz,
        opnd_create_instr(indirect_link_notification_jump)));

    // { %rbx=to, %temp1=from } : jump to shadow stack resolution
    APP(ilist, shadow_stack_resolution_jump);

    // { %rbx=to, %temp1=from, %temp2=%ssp } : save any changes to the shadow stack pointer
    APP(ilist, SAVE_TO_TLS(dcontext,
        TEMP_REGISTER2,
        TLS_SHADOW_STACK_POINTER));

    // { %rbx=to, %temp1=from } : check flag 'unexpected return'
    APP(ilist, INSTR_CREATE_test(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_UNEXPECTED_RETURN)));

    // { %rbx=to, %temp1=from } : flag is off: it's an expected return so skip CS IBP
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jz,
        opnd_create_instr(restore_temp1)));

    // { %rbx=to }
    APP(ilist, indirect_link_notification_jump);

    // { %rbx=to } : restore app contents of %temp1
    APP(ilist, restore_temp1);

    // { %rbx=to, %temp1=! } : restore app contents of %temp2
    APP(ilist, RESTORE_FROM_TLS(dcontext,
        TEMP_REGISTER2,
        TLS_TEMP_REGISTER2));

    track_ibl_routine(ibl_routine_start_pc);

    top_level_jump_targets->shadow_stack_resolution_return = shadow_stack_resolution_jump->next;
    top_level_jump_targets->indirect_link_notification_return = indirect_link_notification_jump->next;
}

void
append_indirect_link_notification(dcontext_t *dcontext, instrlist_t *ilist, ibl_code_t *ibl_code,
        instr_t *fragment_not_found) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    if (!is_tracked_ibl_routine(ibl_code->indirect_branch_lookup_routine)) {
        CS_WARN("Skipping instrumentation of untracked ibl routine at %x\n", ibl_code->indirect_branch_lookup_routine);
        return;
    }

    append_indirect_branch_pairing_routine(dcontext, ilist, ibl_code, fragment_not_found);
    append_shadow_stack_resolution_routine(dcontext, ilist, ibl_code, fragment_not_found);
}

void
notify_emitting_instruction(instr_t *instr, cache_pc pc) {
    CROWD_SAFE_DEBUG_HOOK_QUIET_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    if (!*gencode_in_progress) return;

#ifdef DEBUG_GENCODE
    /*
    if (instr == indirect_link_notification_start) {
        //dr_fprintf(breakpoint_file, "# break at crowd-safe IBL loop in ibl routine at "PX"\n",
        //    instrumented_ibl_routine_start_pcs[*iirsp_index-1]);
        dr_fprintf(breakpoint_file, "break *"PX"\n", instrumented_ibl_routine_start_pcs[*iirsp_index-1]);
        indirect_link_notification_start = (instr_t *) int2p((uint64) -1L);
    }
    */

    /*
    if (instr == top_level_jump_targets->ibl_found_hook) {
        dr_fprintf(breakpoint_file,
            DEBUG_SCRIPT_COMMENT("break at crowd-safe IBP hook in ibl routine at "PX"\n"),
            drvector_get_entry(instrumented_ibl_routine_start_pcs, instrumented_ibl_routine_start_pcs->entries-1));
        dr_fprintf(breakpoint_file, BREAKPOINT, pc);
    }
    */
#endif

    if (instr == top_level_jump_targets->indirect_link_notification_start) {
        CS_LOG("IBL routine at "PX", CS IBP "PX"\n",
            drvector_get_entry(instrumented_ibl_routine_start_pcs, instrumented_ibl_routine_start_pcs->entries-1), pc);
#ifdef DEBUG_GENCODE
        dr_fprintf(breakpoint_file,
            DEBUG_SCRIPT_COMMENT("break at crowd-safe IBP loop in ibl routine at 0x%x\n"),
            drvector_get_entry(instrumented_ibl_routine_start_pcs, instrumented_ibl_routine_start_pcs->entries-1));

        // set the breakpoint at the IBP routine
        // dr_fprintf(breakpoint_file, BREAKPOINT, pc);
        dr_fprintf(breakpoint_file, BREAKPOINT_CONDITIONAL, pc, "@esi != 0x12345678");
#endif
        // clear the reference, because this address will soon be a different instruction
        top_level_jump_targets->indirect_link_notification_start = (instr_t *) PC(0);
    } else if (instr == top_level_jump_targets->shadow_stack_resolution_start) {
        CS_LOG("IBL routine at "PX", shadow stack "PX"\n",
            drvector_get_entry(instrumented_ibl_routine_start_pcs, instrumented_ibl_routine_start_pcs->entries-1), pc);
        //dr_fprintf(breakpoint_file,
        //    DEBUG_SCRIPT_COMMENT("break at crowd-safe shadow stack resolution in ibl routine at "PX"\n"),
        //    instrumented_ibl_routine_start_pcs[(*iirsp_index)-1]);
        //dr_fprintf(breakpoint_file, BREAKPOINT, pc);
    }
}

void
track_ibl_routine(byte *pc) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (CROWD_SAFE_BB_GRAPH())
        drvector_append(instrumented_ibl_routine_start_pcs, pc);
}

#ifdef WINDOWS
void
track_shared_syscall_routine(byte *pc) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    CS_DET("Shared syscall routine at 0x%p\n", pc);
    drvector_append(instrumented_syscall_routine_entry_points, pc);
}
#endif

void
destroy_crowd_safe_gencode() {
    CS_LOG("Destroying CrowdSafe gencode.\n");

    dr_global_free(gencode_in_progress, sizeof(bool));

    drvector_delete(instrumented_ibl_routine_start_pcs);
    drvector_delete(instrumented_syscall_routine_entry_points);
    dr_global_free(instrumented_ibl_routine_start_pcs, sizeof(drvector_t));
    dr_global_free(instrumented_syscall_routine_entry_points, sizeof(drvector_t));

#ifdef DEBUG_GENCODE
    dr_close_file(breakpoint_file);
#endif
}

/**** Private Functions ****/

static int
get_ibl_start_pc_index(byte *ibl_start_pc) {
    uint i = 0;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, -1);

    for (; i < instrumented_ibl_routine_start_pcs->entries; i++)
        if (drvector_get_entry(instrumented_ibl_routine_start_pcs, i) == ibl_start_pc)
            return i;
    return -1;
}

static bool
is_tracked_ibl_routine(byte *pc) {
    return get_ibl_start_pc_index(pc) >= 0;
}

static bool
is_tracked_syscall_routine(byte *pc) {
    uint i;

    for (i = 0; i < instrumented_syscall_routine_entry_points->entries; i++)
        if (drvector_get_entry(instrumented_syscall_routine_entry_points, i) == pc)
            return true;
    return false;
}

static inline void
append_indirect_branch_pairing_routine(dcontext_t *dcontext, instrlist_t *ilist, ibl_code_t *ibl_code, instr_t *fragment_not_found) {
    instr_t *is_bucket_match, *is_bucket_empty, *is_bucket_end_sentinel, *loop_to_table_start, *step_to_next_bucket;

    /********** branch targets ***********/

#ifdef X64
    // { %rbx=to, %temp1=hash, %temp2=index } : compare hash with current bucket
    is_bucket_match = INSTR_CREATE_cmp(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, 0));
#else
    // { %rbx=to, %temp1=hash, %temp2=index } : compare hash with current bucket
    is_bucket_match = INSTR_CREATE_cmp(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, HASH_BUCKET_HASH));
#endif

    // cs-todo: empty and end sentinel checks may not be so simple in x64

    // { %rbx=to, %temp1=hash, %temp2=index }
    is_bucket_empty = INSTR_CREATE_cmp(dcontext,
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, HASH_BUCKET_TO),
        OPND_CREATE_INT32(0));

    // { %rbx=to, %temp1=hash, %temp2=index }
    is_bucket_end_sentinel = INSTR_CREATE_cmp(dcontext,
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, HASH_BUCKET_TO),
        OPND_CREATE_INT32(1)); // top half of IBP_HASHTABLE_END_SENTINEL

    // { %rbx=to, %temp1=hash, %temp2=index } : load the table start into %temp2
    loop_to_table_start = INSTR_CREATE_mov_ld(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_TLS_FIELD(TLS_IBP_SLOT));

    // { %rbx=to, %temp1=hash, %temp2=index }
    step_to_next_bucket = INSTR_CREATE_add(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_CREATE_INT8(sizeof(bb_tag_pairing_t)));

    /********** instruction sequence ***********/

#ifdef X64

    // [hash = from ^ to] [xor %rbx %temp1] : { %rbx=to, %temp1=hash-in-progress }
    APP(ilist, top_level_jump_targets->indirect_link_notification_start);

    APP(ilist, INSTR_CREATE_xor(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        opnd_create_reg(REG_XBX)));

    // [hash = hash & 0x00000000FFFFFFFFFULL] [and C %temp1] : { %rbx=to, %temp1=hash-in-progress }
    APP(ilist, INSTR_CREATE_and(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        OPND_CREATE_INT32(ALL_LOWER_BITS & 0x7FFFFFFFUL))); // cs-hack

    // [a = to] [mov %rbx %temp2] : { %rbx=to, %temp1=hash-in-progress }
    APP(ilist, INSTR_CREATE_mov_ld(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        opnd_create_reg(REG_XBX)));

    // [a << 32] [shl 0x20 %temp2] : { %rbx=to, %temp1=hash-in-progress, %temp2=to }
    APP(ilist, INSTR_CREATE_shl(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_CREATE_INT8(0x20)));

    // [hash = a | hash] [or %temp2 %temp1] : { %rbx=to, %temp1=hash, %temp2=(to<<32) }
    APP(ilist, INSTR_CREATE_or(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        opnd_create_reg(TEMP_REGISTER2)));

    // hash is <%temp1> : <mask32(to) + mask32((from <<o 1) ^ to)>

#else

    // [hash_a = from <<o 1] [rol %temp1] : { %rbx=to, %temp1=from }
    APP(ilist, top_level_jump_targets->indirect_link_notification_start);

    // [hash_a = (from <<o 1) ^ to] [xor %rbx %temp1] : { %rbx=to, %temp1=(from <<o 1) }
    APP(ilist, INSTR_CREATE_xor(dcontext,
        opnd_create_reg(TEMP_REGISTER1),
        opnd_create_reg(REG_XBX)));

    // hash is <%rbx,%temp1> : <to, (from <<o 1) ^ to>

#endif

    // { %rbx=to, %temp1=hash } : load mask into %temp2
    APP(ilist, INSTR_CREATE_mov_ld(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_TLS_FIELD(TLS_IBP_MASK_SLOT)));

    // { %rbx=to, %temp1=hash, %temp2=mask } : apply mask to %temp2
    APP(ilist, INSTR_CREATE_and(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        opnd_create_reg(TEMP_REGISTER1)));

    // { %rbx=to, %temp1=hash, %temp2=index } : expand index to bucket size
    APP(ilist, INSTR_CREATE_shl(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_CREATE_INT8(HASH_BUCKET_INDEX_EXPANSION)));

    // { %rbx=to, %temp1=hash, %temp2=index } : raise index into the hashtable
    APP(ilist, INSTR_CREATE_add(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_TLS_FIELD(TLS_IBP_SLOT)));

    // { %rbx=to, %temp1=hash, %temp2=index } : compare hash with current bucket
    APP(ilist, is_bucket_match);

    // { %rbx=to, %temp1=hash, %temp2=index } : no match--jump to miss
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jne,
        opnd_create_instr(is_bucket_empty)));

#ifndef X64

    // { %rbx=to, %temp1=hash, %temp2=index } : compare the upper half of the IBP
    APP(ilist, INSTR_CREATE_cmp(dcontext,
        opnd_create_reg(REG_XBX),
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, HASH_BUCKET_TO)));

    // { %rbx=to, %temp1=hash, %temp2=index } : no match--jump to miss
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jne,
        opnd_create_instr(is_bucket_empty)));

#endif

    // { %rbx=to, %temp1=hash, %temp2=index } : consume ibp `from`
    APP(ilist, INSTR_CREATE_mov_st(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FROM_TAG),
        OPND_CREATE_INT32(0UL)));

    // { %rbx=to, %temp1=hash, %temp2=index } : it's a match, so continue in the fcache
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(top_level_jump_targets->indirect_link_notification_return)));

    // { %rbx=to, %temp1=hash, %temp2=index }
    APP(ilist, is_bucket_empty); /* cmp HASH_BUCKET_TO, 0 */

    // { %rbx=to, %temp1=hash, %temp2=index } : the bucket is not empty: check for end sentinel
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jne,
        opnd_create_instr(is_bucket_end_sentinel)));

    // { %rbx=to, %temp1=hash, %temp2=index } : mark ibp_data contents as containing a new path
    APP(ilist, INSTR_CREATE_or(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_NEW_PATH)));

    // { %rbx=to, %temp1=hash, %temp2=index } : restore %temp1
    APP(ilist, RESTORE_FROM_TLS(dcontext,
        TEMP_REGISTER1,
        TLS_TEMP_REGISTER1));

    // { %rbx=to, %temp2=index } : restore %temp2
    APP(ilist, RESTORE_FROM_TLS(dcontext,
        TEMP_REGISTER2,
        TLS_TEMP_REGISTER2));

    // { %rbx=to } : take the "not found" path to dispatch()
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(fragment_not_found)));

    // { %rbx=to, %temp1=hash, %temp2=index }
    APP(ilist, is_bucket_end_sentinel);

    // { %rbx=to, %temp1=hash, %temp2=index } : end sentinel yes: jump to the table loopback
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_je,
        opnd_create_instr(loop_to_table_start)));

    // { %rbx=to, %temp1=hash, %temp2=index }
    APP(ilist, step_to_next_bucket);

    // { %rbx=to, %temp1=hash, %temp2=index } : jump to comparison of target with current bucket
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(is_bucket_match)));

    // { %rbx=to, %temp1=hash, %temp2=index } : load the table start into %temp2
    APP(ilist, loop_to_table_start);

    // { %rbx=to, %temp1=hash, %temp2=index } : jump to comparison of target with current bucket
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(is_bucket_match)));
}

static inline void
append_shadow_stack_resolution_routine(dcontext_t *dcontext, instrlist_t *ilist,
                                       ibl_code_t *ibl_code, instr_t *fragment_not_found) {
    instr_t *unexpected_return_handler;
    instr_t *unwind_shadow_stack_loop;
    instr_t *unset_stack_pending;
    extern bool verify_shadow_stack;

    if (false && verify_shadow_stack) {

        // { %rbx=to } : restore %temp2
        APP(ilist, top_level_jump_targets->shadow_stack_resolution_start);

        // { %rbx=to, %temp1=hash, %temp2=index } : restore %temp1
        APP(ilist, RESTORE_FROM_TLS(dcontext,
            TEMP_REGISTER1,
            TLS_TEMP_REGISTER1));

        // { %rbx=to } : take the "not found" path to dispatch()
        APP(ilist, INSTR_CREATE_jcc(dcontext,
            OP_jmp,
            opnd_create_instr(fragment_not_found)));

        return;
    }

    /********** branch targets ***********/

    // { %rbx=to, %temp2=%ssp } : set 'unexpected return' flag
    unexpected_return_handler = INSTR_CREATE_or(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_UNEXPECTED_RETURN));

    // { %rbx=to, %temp2=%ssp } : check shadow stack frame for context bottom sentinel
    unwind_shadow_stack_loop = INSTR_CREATE_cmp(dcontext,
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, -(int)sizeof(app_pc)),
        OPND_CREATE_INTPTR(SHADOW_STACK_SENTINEL));

    unset_stack_pending = INSTR_CREATE_and(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(~IBP_META_STACK_PENDING & 0x7FFFFFFFUL));

    /********** instruction sequence ***********/

    // { %rbx=to } : load %ssp into %temp2
    APP(ilist, top_level_jump_targets->shadow_stack_resolution_start);

    // { %rbx=to, %temp2=%ssp } : compare %sbp with %rsp (equivalent to %sbp - %rsp)
    APP(ilist, INSTR_CREATE_cmp(dcontext,
        opnd_create_reg(REG_XSP),
        OPND_TLS_FIELD(TLS_STACK_SPY_MARK)));

    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jb,
        opnd_create_instr(unset_stack_pending)));

    // terminate spy mode
    APP(ilist, INSTR_CREATE_mov_st(dcontext,
        OPND_TLS_FIELD(TLS_STACK_SPY_MARK),
        OPND_CREATE_INT32(0UL)));

    // { %rbx=to, %temp2=%ssp } : unset the 'stack pending' flag
    APP(ilist, unset_stack_pending);

    // { %rbx=to, %temp2=%ssp } : compare shadow stack's expected return with `to`
    APP(ilist, INSTR_CREATE_cmp(dcontext,
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, -(int)sizeof(shadow_stack_frame_t)),
        opnd_create_reg(REG_XBX)));

    // { %rbx=to, %temp2=%ssp } : not equal: jump to unexpected return handler
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jne,
        opnd_create_instr(unexpected_return_handler)));

    // { %rbx=to, %temp2=%ssp } : equal: pop a shadow stack frame off %temp2
    APP(ilist, INSTR_CREATE_sub(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_CREATE_INT8(sizeof(shadow_stack_frame_t))));

    // { %rbx=to, %temp2=%ssp } : flip the return bit for next time (it's inverted, so 1 = "not a return")
    APP(ilist, INSTR_CREATE_or(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_RETURN)));

    // { %rbx=to, %temp2=%ssp } : consume ibp `from`
    APP(ilist, INSTR_CREATE_mov_st(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FROM_TAG),
        OPND_CREATE_INT32(0UL)));

    // { %rbx=to, %temp2=%ssp } : jump back to shadow_stack_resolution_return
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(top_level_jump_targets->shadow_stack_resolution_return)));

    // { %rbx=to, %temp2=%ssp } : set 'unexpected return' flag
    APP(ilist, unexpected_return_handler);

    // { %rbx=to, %temp2=%ssp } : save the shadow stack miss frame to TLS
    APP(ilist, SAVE_TO_TLS(dcontext,
        TEMP_REGISTER2,
        TLS_SS_MISS_FRAME));

    // { %rbx=to, %temp2=%ssp } : check shadow stack frame for context bottom sentinel
    APP(ilist, unwind_shadow_stack_loop);

    // { %rbx=to, %temp2=%ssp } : hit shadow stack bottom, so jump to shadow_stack_resolution_return
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_je,
        opnd_create_instr(top_level_jump_targets->shadow_stack_resolution_return)));

    // { %rbx=to, %temp2=%ssp } : compare %sbp with %rsp (equivalent to %sbp - %rsp)
    APP(ilist, INSTR_CREATE_cmp(dcontext,
        opnd_create_reg(REG_XSP),
        OPND_CREATE_MEMPTR(TEMP_REGISTER2, -(int)sizeof(app_pc))));

    // { %rbx=to, %temp2=%ssp } : found matching stack level, so jump to shadow_stack_resolution_return
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jle,
        opnd_create_instr(top_level_jump_targets->shadow_stack_resolution_return)));

    // { %rbx=to, %temp2=%ssp } : pop a shadow stack frame from %temp2
    APP(ilist, INSTR_CREATE_sub(dcontext,
        opnd_create_reg(TEMP_REGISTER2),
        OPND_CREATE_INT8(sizeof(shadow_stack_frame_t))));

    // { %rbx=to, %temp2=%ssp } : jump to top of unwind loop
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jmp,
        opnd_create_instr(unwind_shadow_stack_loop)));
}
