#include "dr_api.h"
#include "dr_ir_instr.h"
#include "basic_block_observer.h"
#include "link_observer.h"
#include "module_observer.h"
#include "crowd_safe_util.h"
#include "crowd_safe_trace.h"
#include "basic_block_hashtable.h"
#include "indirect_link_observer.h"
#include "indirect_link_hashtable.h"
#include "execution_monitor.h"
#include "blacklist.h"

#ifdef WINDOWS
# include <windows.h>
#endif

/**** Public Fields ****/

app_pc *dll_entry_callback_block;

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
app_pc *kernel_base_get_proc_address;
#endif

/**** Private Fields ****/

static const uint64 GRAPH_META_HASH_PLACEHOLDER = 0ULL;

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
static app_pc *kernel_base_get_proc_address_return;
#endif

#ifdef DEBUG
drvector_t *ibp_witness_list;
#endif;

// removed `instr_set_our_mangling(instr, true);` b/c it's client instrumentation
#define PRE(target, added_size, instr_expr) \
do { \
    instr_t *instr = instr_expr; \
    added_size += instr_length(dcontext, instr); \
    instr_set_translation(instr, instr_get_app_pc(target)); \
    instrlist_preinsert(ilist, target, instr); \
} while (0);

#define POST(target, added_size, instr_expr) \
do { \
    instr_t *instr = instr_expr; \
    added_size += instr_length(dcontext, instr); \
    instr_set_translation(instr, instr_get_app_pc(target)); \
    instrlist_postinsert(ilist, target, instr); \
} while (0);

/* needs translation to be set on `instr`
#define APP(instr_expr) \
do { \
    instr_t *instr = instr_expr; \
    instrlist_meta_append(ilist, instr); \
} while (0);
*/

//CS_TRACK(instr, sizeof(instr_t));

#define SHIFT_IN_EMPTY_BYTES(data, bytes_to_keep) \
    (data << ((4 - bytes_to_keep)*8)) >> ((4 - bytes_to_keep)*8)

#define IS_CALL_GATE(i) ((instr_get_length(i) == 7) && (*(uint*)instr_get_translation(i) == 0xc015ff64) && \
    ((*((uint*)instr_get_translation(i) + 1) << 0x10) == 0))

#define CALL_WILL_RETURN(i) (!instr_is_syscall(i))

#define IS_SYSCALL_TRAMPOLINE(tag, bounds) ((tag >= bounds.start_pc) && (tag <= bounds.end_pc))
#define IS_DIFFERENT_IMAGE(location, state) \
    ((location->type == module_type_image) && (location->image_instance_id != state->image_instance_id))

#define FUNCTION_PADDING_SIGNATURE_WOW64 0xccccccccU
#define FUNCTION_PADDING_SIGNATURE_X86 0x90909090U

#define MULTIMAP_NAME_KEY black_box_hash_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE bb_hash_t
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_NAME_KEY black_box_hash_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE bb_hash_t
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimapx.h"

typedef struct syscall_trampolines_t syscall_trampolines_t;
struct syscall_trampolines_t {
    app_pc start_pc;
    app_pc end_pc;
};

static syscall_trampolines_t syscall_trampolines_nt;
static syscall_trampolines_t syscall_trampolines_zw;

#define FIRST_NT_SYSCALL "NtAcceptConnectPort"
#define LAST_NT_SYSCALL "NtYieldExecution"
#define FIRST_ZW_SYSCALL "ZwMapUserPhysicalPagesScatter"
#define LAST_ZW_SYSCALL "ZwWow64CallFunction64"

#ifdef DEBUG // spec hack
static app_pc *libiomp5md_start;
#endif

/**** Private Prototypes ****/

static bb_hash_t
hash_bits(bb_hash_t hash, uint length, byte *bits);

static bool
commit_basic_block(dcontext_t *dcontext, app_pc tag, bb_hash_t hash,
    graph_meta_type meta_type, module_location_t *location, app_pc pending_cti_target_pc, ushort bb_size);

static ushort
get_opcode_length(byte *instr_raw_bits);

static bool
has_relocatable_operands(instr_t *i);

#ifdef UNIX
static trampoline_tracker*
create_trampoline_tracker(app_pc tag, app_pc plt_cell);
#endif

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
static void
instrument_get_proc_address_entry(dcontext_t *dcontext, instrlist_t *ilist, instr_t *insert_before);

static void
instrument_get_proc_address_return(dcontext_t *dcontext, instrlist_t *ilist, instr_t *insert_before);
#endif

/**** Public Functions ****/

void
init_basic_block_observer(bool isFork) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    dll_entry_callback_block = (app_pc*)CS_ALLOC(sizeof(app_pc));
    *dll_entry_callback_block = NULL;

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
    kernel_base_get_proc_address = (app_pc*)CS_ALLOC(sizeof(app_pc));
    *kernel_base_get_proc_address = NULL;
    kernel_base_get_proc_address_return = (app_pc*)CS_ALLOC(sizeof(app_pc));
    *kernel_base_get_proc_address_return = NULL;
#endif

#ifdef DEBUG
    ibp_witness_list = (drvector_t *)CS_ALLOC(sizeof(drvector_t));
    drvector_init(ibp_witness_list, 10U, false, NULL);

    // spec hack
    libiomp5md_start = CS_ALLOC(sizeof(app_pc));
    *libiomp5md_start = 0;
#endif

    syscall_trampolines_nt.start_pc = dr_get_ntdll_proc_address(FIRST_NT_SYSCALL);
    syscall_trampolines_nt.end_pc = dr_get_ntdll_proc_address(LAST_NT_SYSCALL);
    CS_DET("Syscall trampolines for Nt: start "PX" and end "PX".\n",
           syscall_trampolines_nt.start_pc, syscall_trampolines_nt.end_pc);

    syscall_trampolines_zw.start_pc = dr_get_ntdll_proc_address(FIRST_ZW_SYSCALL);
    syscall_trampolines_zw.end_pc = dr_get_ntdll_proc_address(LAST_ZW_SYSCALL);
    CS_DET("Syscall trampolines for Zw: start "PX" and end "PX".\n",
           syscall_trampolines_zw.start_pc, syscall_trampolines_zw.end_pc);
}

void
write_graph_metadata() {
    app_pc s;
    bb_state_t meta_node_state = { 0, BB_STATE_LIVE | BB_STATE_SINGLETON | BB_STATE_COMMITTED, 0ULL, graph_meta_singleton, 0 };

    hashcode_lock_acquire();

    meta_node_state.hash = PROCESS_ENTRY_HASH;
    insert_bb_state(PROCESS_ENTRY_POINT, meta_node_state);

    meta_node_state.hash = SYSTEM_ENTRY_HASH;
    insert_bb_state(SYSTEM_ENTRY_POINT, meta_node_state);

    meta_node_state.hash = CHILD_PROCESS_SINGLETON_HASH;
    insert_bb_state(CHILD_PROCESS_SINGLETON_PC, meta_node_state);

    meta_node_state.hash = SYSCALL_SINGLETON_HASH;
    for (s = SYSCALL_SINGLETON_START; s < SYSCALL_SINGLETON_END; s++)
        insert_bb_state(s, meta_node_state);

    hashcode_lock_release();
}

void
notify_basic_block_constructed(dcontext_t *dcontext, app_pc tag, instrlist_t *ilist,
                               bool has_syscall, int syscall_number)
{
    bb_hash_t hash = 0ULL;
    instr_t *i;
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    instr_t *call_instr = NULL;
    byte meta_type = graph_non_meta;
    module_location_t *location;
    short next_relocation;
    byte normalization_buffer[15];
    app_pc continuation_pc = NULL;
    app_pc pending_cti_target_pc = NULL;
    byte current_ordinal = 0;
    ushort bb_size = 0;
    //module_data_t *main_module = dr_get_main_module(); // cs-hack: winsock

#ifdef UNIX
    trampoline_tracker *trampoline;
#endif
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (tag == int2p(0x772e8e57)) { /* hardcoding the exit syscall, which is not subject to ASLR */
        extern uint64 process_start_time;
        uint64 process_end_time = dr_get_milliseconds();
        dr_printf("Process exiting after %d milliseconds\n", (uint)(process_end_time - process_start_time));
        dr_exit_process(0);
    }

    start_decoding(cstl, tag);

    location = get_module_for_address(tag);
    if ((location == NULL) || (location == &unknown_module))
        CS_ERR("Tag "PX" occurs in %s module!\n", tag, (location == NULL) ? "no" : "the unknown");

    {
        extern bool verify_shadow_stack;
        if (verify_shadow_stack)
            log_shadow_stack(dcontext, cstl->csd, " ==uknown module==");
    }

#ifdef GENCODE_CHUNK_STUDY
    if (location->type == module_type_anonymous)
        notify_shadow_page_decode(tag);
#endif

#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_DETAILS) || defined(LOG_ANONYMOUS_ASSEMBLY)
    if (location->type != module_type_image)
        CS_LOG("\n ==== anonymous bb "PX" ====\n", tag);
#endif

    i = instrlist_first(ilist);

    if (instr_get_opcode(i) == OP_jmp) {
        opnd_t src0 = instr_get_src(i, 0);
        module_location_t *jump_target_module;

        ASSERT(instr_get_next(i) == NULL);
        ASSERT(opnd_is_pc(src0));

        jump_target_module = get_module_for_address(opnd_get_pc(src0));
        if (location != jump_target_module) {
            hash = (bb_hash_t)OP_jmp; // it must be instrumented, so discard the operand and skip the loop

#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_DETAILS) || defined(LOG_ANONYMOUS_ASSEMBLY)
            disassemble(dcontext, instr_get_translation(i), cs_log_file);
#endif
        }
    } else if ((IS_SYSCALL_TRAMPOLINE(tag, syscall_trampolines_nt) ||
        IS_SYSCALL_TRAMPOLINE(tag, syscall_trampolines_zw)) &&
        (instr_get_opcode(i) != OP_ret) && (instr_get_opcode(i) != OP_add))
    {
        instr_t *i2 = instr_get_next(i);
        opnd_t src0 = instr_get_src(i2, 0);

        ASSERT(i2 != NULL);

        if (opnd_is_immed_int(src0)) {
            app_pc target_address = int2p(opnd_get_immed_int(src0));
            module_location_t *target_module = get_module_for_address(target_address);
            instr_t *i3 = instr_get_next(i2);

            if ((target_module->type == module_type_anonymous) && (i3 != NULL) && (instr_get_opcode(i3) == OP_jmp_ind)) {
                int i2_opcode = instr_get_opcode(i2);
                hash = hash_bits(hash, instr_length(dcontext, i), instr_get_raw_bits(i));
                hash = hash_bits(hash, 4, (byte *) &i2_opcode);
                hash = hash_bits(hash, instr_length(dcontext, i3), instr_get_raw_bits(i3));

                CS_DET("Normalized hash for syscall hook "PX" -> "PX" is 0x%llx\n", tag, target_address, hash);
            }
        }
    }

    if (hash == 0ULL) {
        for (; i != NULL; i = instr_get_next(i)) {
            ushort length = (ushort)instr_length(dcontext, i);
            uint opcode = instr_get_opcode(i);
            byte *instr_bits = instr_get_raw_bits(i);
            byte *norm_instr_bits = instr_bits;
            ushort b;

            bb_size += length;

            if (instr_bits == NULL) {
                CS_WARN("Instruction bits are null for opcode 0x%02x and length %d. Skipping hashcode!\n", opcode, length);
                continue;
            }

#ifdef UNIX
            if ((opcode == 0x30) && (instr_get_next(i) == NULL)) {
                app_pc jump_target = instr_get_src(i, 0)->value.addr;
                void *exists = hashtable_lookup(plt_stubs, jump_target);
                if (exists != NULL) {
                    trampoline = create_trampoline_tracker(tag, jump_target);
                    meta_type = graph_meta_trampoline;
                }
            } else
#endif
            if (instr_is_call(i)) {
                if (CALL_WILL_RETURN(i)) {
                    continuation_pc = instr_get_app_pc(i) + length;
                    if (*dll_entry_callback_block == NULL) {
                        if (dr_is_dll_entry_callback(continuation_pc))
                            *dll_entry_callback_block = tag;
                    }

                    ASSERT(instr_get_next(i) == NULL);
                    call_instr = i;
                }
            } else if (instr_is_return(i)) {
                meta_type = graph_meta_return;
            }

            if (instr_is_syscall(i)) {
                ASSERT(has_syscall);

                continuation_pc = instr_get_app_pc(i) + length;
                current_ordinal++;
                if (syscall_number < 0) {
                    hashcode_lock_acquire();
                    insert_dso_entry(dcontext, tag);
                    hashcode_lock_release();
               } else {
                   SET_STATIC_SYSCALL_ORDINAL(cstl, current_ordinal);
               }
            }

            /*
            if (location->type == module_type_anonymous && instr_is_cti(i)) {
                opnd_t target = instr_get_target(i);
                if (target.kind == PC_kind)
                    pending_cti_target_pc = target.value.pc;
            }
            */

            if (instr_is_cbr(i))
                current_ordinal += 2;
            else if (instr_is_cti(i))
                current_ordinal++;

            if (location->type == module_type_image) { // relocation is not available for other module types
                if (location->relocation_table != NULL) {
                    next_relocation = get_next_relocation(location, instr_get_translation(i),
                                      instr_get_translation(i) + length);
                    if (next_relocation >= 0) {
                        norm_instr_bits = normalization_buffer;
                        for (b = 0; b <= length; b++) {
                            if (b == next_relocation) {
                                uint normalized = *(uint*)(instr_bits + b);
                                normalized -= (uint)location->start_pc;
                                *(uint*)(norm_instr_bits + b) = normalized;
                                b += 3;
                                if (b <= (length - 4)) {
                                    next_relocation = get_next_relocation(location, instr_get_translation(i) + b,
                                                                          instr_get_translation(i) + length);
                                    if (next_relocation >= 0)
                                        next_relocation += b;
                                } else {
                                    next_relocation = (short)-1;
                                }
                            } else {
                                norm_instr_bits[b] = instr_bits[b];
                            }
                        }
                    }
                }
            } else {
                if (has_relocatable_operands(i)) {
                    length = get_opcode_length(instr_bits);
                }

#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_DETAILS) || defined(LOG_ANONYMOUS_ASSEMBLY)
                disassemble(dcontext, instr_get_translation(i), cs_log_file);
#endif
            }

            hash = hash_bits(hash, length, norm_instr_bits);
        }
    }

#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_DETAILS) || defined(LOG_ANONYMOUS_ASSEMBLY)
    if (location->type != module_type_image)
        CS_LOG(" ==== end anonymous bb "PX" with hash 0x%llx ====\n", tag, hash);
#endif

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
    if (tag == *kernel_base_get_proc_address) {
        uint *function_scanner = (uint*)*kernel_base_get_proc_address;
        while ((*function_scanner != FUNCTION_PADDING_SIGNATURE_WOW64) &&
            (*function_scanner != FUNCTION_PADDING_SIGNATURE_X86))
            function_scanner = (uint*)(((byte*)function_scanner) + 1);
        *kernel_base_get_proc_address_return = (app_pc)((uint)function_scanner - 9U);

        CS_LOG("Found kernelbase!GetProcAddress entry block at "PX"\n", tag);

        instrument_get_proc_address_entry(dcontext, ilist, instrlist_first(ilist));
    } if (tag == *kernel_base_get_proc_address_return) {
        CS_LOG("Found kernelbase!GetProcAddress return block at "PX"\n", tag);
        instrument_get_proc_address_return(dcontext, ilist, instrlist_first(ilist)->next);
    }
#endif

    if (continuation_pc != NULL)
        add_pending_edge(tag, continuation_pc, current_ordinal, call_continuation_edge, location, location, false);
    if (call_instr != NULL)
        dr_instrument_call_site(dcontext, ilist, call_instr);

    if (has_syscall && (syscall_number >= 0)) {
        ASSERT(syscall_number < (SYSCALL_SINGLETON_END - SYSCALL_SINGLETON_START));

        SET_STATIC_SYSCALL_NUMBER(cstl, syscall_number);
    }
    commit_basic_block(dcontext, tag, hash, meta_type, location, pending_cti_target_pc, bb_size);
}

void
notify_trace_constructed(dcontext_t *dcontext, instrlist_t *ilist) {
    instr_t *i, *next;

    for (i = instrlist_first(ilist); i != NULL; i = next) {
        next = instr_get_next(i);
        if (instr_is_call(i) && CALL_WILL_RETURN(i))
            dr_instrument_call_site(dcontext, ilist, i);
    }
}

void
notify_basic_block_removed(dcontext_t *dcontext, app_pc tag) {
    ibp_tag_remove(dcontext, tag); // will remove xrefs

    hashcode_lock_acquire();
    deactivate_bb(tag);
    hashcode_lock_release();

    // cs-todo: also remove pending edges?
}

void
notify_cache_reset(dcontext_t *dcontext) {
    CS_WARN("Cache reset!\n");

    ibp_clear(dcontext);

    hashcode_lock_acquire();
    deactivate_all();
    hashcode_lock_release();
}

void
crowd_safe_thread_reset(dcontext_t *dcontext) {
    //ibp_hash_clear(dcontext);
}

#ifdef DEBUG
void
ibp_testify(app_pc tag) {
    uint i;
    bool witnessed = false;
    bb_state_t *state;

    if (is_monitor_active())
        return;

    hashcode_lock_acquire();
    state = get_bb_state(tag);
    if ((state == NULL) || !IS_BB_LIVE(state)) {
        for (i = 0; i < ibp_witness_list->entries; i++) {
            if (ibp_witness_list->array[i] == tag) {
                witnessed = true;
                break;
            }
        }
        if (!witnessed && (get_ibp_edge_count(tag) == 0)) {
            drvector_append(ibp_witness_list, tag);
        }
    }
    hashcode_lock_release();
}
#endif

void
close_basic_block_observer() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);
}

/**** Private Functions ****/

static inline bb_hash_t
hash_bits(bb_hash_t hash, uint length, byte *bits) {
    ushort b;

    while (length > 3) {
        hash = hash ^ (hash << 5) ^ *(uint *)(bits);
        length -= 4;
        bits += 4;
    }
    if (length != 0) {
        uint tail = 0UL;
        for (b = 0; b < length; b++)
            tail |= ((uint)(*(bits + b)) << (b * 8));
        tail = SHIFT_IN_EMPTY_BYTES(tail, length);
        hash = hash ^ (hash << 5) ^ tail;
    }

    if (hash == 0ULL)
        return 0xffffffULL; // cannot use a zero hash, so substitute with a very unlikely hash
    else
        return hash;
}

static inline bool
commit_basic_block(dcontext_t *dcontext, app_pc tag, bb_hash_t hash,
    graph_meta_type meta_type, module_location_t *location, app_pc pending_cti_target_pc, ushort bb_size)
{
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    bb_state_t *state;
    bool is_new_tag_version = false;

    ASSERT(IS_BUILDING_TAG(cstl, tag));
    hashcode_lock_acquire();

    state = get_bb_state(tag);

    /*
    DODEBUG({
        if (!is_monitor_active() && (get_ibp_edge_count(tag) > 0)) {
            uint i;
            bool witnessed = false;
            for (i = 0; i < ibp_witness_list->entries; i++) {
                if (ibp_witness_list->array[i] == tag) {
                    drvector_remove(ibp_witness_list, i);
                    witnessed = true;
                    break;
                }
            }
            if (!witnessed)
                CS_ERR("Witnessed no indirect branches to "PX"\n", tag);
            ASSERT(witnessed);
        }
    });
    */

    if (state != NULL) {
        bool repeated_black_box_decode = false;

        RESET_BB_COMMITTED(state);
        RESET_BB_LINKED(state);
        state->size = bb_size;

        if (IS_BB_BLACK_BOX(state)) {
            repeated_black_box_decode = (GET_LAST_DECODED_TAG(cstl) == tag);
        }

        //CS_LOG("Activating BB "PFX" for commit\n", tag);
        if (IS_BB_LIVE(state))
            CS_WARN("BB "PX" is already live!\n", tag);
        else
            CS_DET("Activate BB "PX"\n", tag);
        ASSERT(!IS_BB_LIVE(state));
        ACTIVATE_BB(state);

        // only increment `tag_version` if the hash changed, since DR will flush an entire
        // page from the code cache anytime a single byte of it is written
        if (((state->hash != hash) || IS_DIFFERENT_IMAGE(location, state)) && !repeated_black_box_decode) {
            if (IS_BB_BLACK_BOX(state)) {
                CS_DET("Clobber black box hash 0x%llx of "PX" at version %d with new hash 0x%llx.\n",
                       state->hash, tag, state->tag_version, hash);

                SET_CLOBBERED_BLACK_BOX_HASH(cstl, state->hash);
                UNSET_BB_BLACK_BOX(state);
            }

            state->hash = hash;
            state->meta_type = meta_type;
            is_new_tag_version = true;

            if (IS_DIFFERENT_IMAGE(location, state)) {
                state->tag_version = 0;
                CS_DET("Resetting tag "PX" to version %d because the containing image instance differs\n", tag, state->tag_version);
            } else {
                state->tag_version++;
                CS_DET("Incrementing tag "PX" to version %d\n", tag, state->tag_version);
            }
        }

        if (IS_BB_COMMITTED(state))
            CS_DET("Linkage pre-approved for "PX" on thread 0x%x\n", tag, current_thread_id());
    }

    if ((GET_LAST_DECODED_TAG(cstl) == tag) && ((state == NULL) || is_new_tag_version))
        CS_WARN("Consecutive decoding of "PX" with differing hashes!\n", tag);

    if ((state == NULL) || is_new_tag_version) {
        if (state == NULL) {
            bb_state_t new_state;
            new_state.image_instance_id = 0;
            new_state.flags = BB_STATE_LIVE;
            new_state.hash = hash;
            new_state.meta_type = meta_type;
            new_state.tag_version = 0;
            new_state.size = bb_size;
            if (IS_EXCEPTION_RESUMING(cstl))
                new_state.flags |= BB_STATE_EXCEPTION;

            state = insert_bb_state(tag, new_state);

            CS_DET("Activate BB "PX"\n", tag);
        }
        if (location->type == module_type_dynamo)
            SET_BB_DYNAMO(state);
        if (is_monitor_active() && ibp_has_incoming_edges(tag))
            SET_BB_LINKED(state);
    } else {
        SET_BB_LINKED(state);
        pending_cti_target_pc = NULL;
    }
    cstl->bb_meta.state = state;

    if (state->hash == 0ULL) {
        CS_ERR("Hash is zero for "PX"!\n", tag);
        ASSERT(state->hash != 0ULL);
    }

    if (location->type == module_type_image)
        state->image_instance_id = location->image_instance_id;
    else
        state->image_instance_id = 0;

    commit_incoming_edges(dcontext, cstl, tag, state, meta_type, location);

    if (pending_cti_target_pc != NULL) {
        CS_DET("Add pending CTI edge "PX" - "PX"\n", tag, pending_cti_target_pc);
        add_pending_edge(tag, pending_cti_target_pc, 0, direct_edge, location, location, true);
    }

    check_blacklist_node(location, tag);

    hashcode_lock_release();

    return true;
}

static inline ushort
get_opcode_length(byte *instr_raw_bits) {
    if (instr_raw_bits[0] == 0x0F) {
        if ((instr_raw_bits[1] == 0x38) || (instr_raw_bits[1] == 0x3A)) {
            return 3;
        }
        return 2;
    }
    return 1;
}

static inline bool
has_relocatable_operands(instr_t *instr) {
    int i;
    opnd_t o;
    for (i = 0; i < instr_num_srcs(instr); i++) {
        o = instr_get_src(instr, i);
        if (opnd_is_abs_addr(o) || opnd_is_pc(o) || opnd_is_immed(o) || opnd_is_base_disp(o))
            return true;
    }
    for (i = 0; i < instr_num_dsts(instr); i++) {
        o = instr_get_dst(instr, i);
        if (opnd_is_abs_addr(o) || opnd_is_pc(o) || opnd_is_immed(o) || opnd_is_base_disp(o))
            return true;
    }
    return false;
}

#ifdef UNIX
static inline trampoline_tracker*
create_trampoline_tracker(app_pc tag, app_pc plt_cell) {
    trampoline_tracker *trampoline = (trampoline_tracker*)CS_ALLOC(sizeof(trampoline_tracker));
    DEBUG_DEFINE(bool ok =) hashtable_add(trampoline_trackers, tag, trampoline);
    ASSERT(ok);
    trampoline->plt_cell = (app_pc*)plt_cell;
    trampoline->trampoline_entry = tag;
    trampoline->function_callers = (drvector_t*)CS_ALLOC(sizeof(drvector_t));
    drvector_init(trampoline->function_callers, 4U, false, free_trampoline_caller);
    trampoline->function_entry = NULL;
    return trampoline;
}
#endif

uint
instrument_return_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag) {
    bool ur;
    bb_state_t *state;

    hashcode_lock_acquire();
    state = get_bb_state(tag);
    ur = IS_BB_UNEXPECTED_RETURN(state);
    hashcode_lock_release();

    if (ur)
        return 0;
    else
        return dr_instrument_return_site(dcontext, ilist, next, tag);
}

/*
    APP(ilist, INSTR_CREATE_test(dcontext,
        OPND_TLS_FIELD(TLS_IBP_FLAGS),
        OPND_CREATE_INT32(IBP_META_RETURN)));

    // { %rbx=to, %temp1=from } : `return=1` so not a return: skip shadow stack resolution
    APP(ilist, INSTR_CREATE_jcc(dcontext,
        OP_jnz,
        opnd_create_instr(indirect_link_notification_jump)));
*/

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
static inline void
instrument_get_proc_address_entry(dcontext_t *dcontext, instrlist_t *ilist, instr_t *insert_before) {
    uint added_size = 0U;

    PRE(insert_before, added_size, INSTR_CREATE_push(dcontext,
        opnd_create_reg(DR_REG_XAX)));
    PRE(insert_before, added_size, INSTR_CREATE_push(dcontext,
        opnd_create_reg(DR_REG_XBX)));

    PRE(insert_before, added_size, INSTR_CREATE_mov_ld(dcontext,
        opnd_create_reg(DR_REG_XAX),
        OPND_CREATE_MEMPTR(DR_REG_XSP, 0x10)));

    PRE(insert_before, added_size, RESTORE_FROM_TLS(dcontext, DR_REG_XBX, TLS_RESOLVED_IMPORTS));

    PRE(insert_before, added_size, INSTR_CREATE_mov_st(dcontext,
        OPND_CREATE_MEMPTR(DR_REG_XBX, 0),
        opnd_create_reg(DR_REG_XAX)));

    PRE(insert_before, added_size, INSTR_CREATE_pop(dcontext,
        opnd_create_reg(DR_REG_XBX)));
    PRE(insert_before, added_size, INSTR_CREATE_pop(dcontext,
        opnd_create_reg(DR_REG_XAX)));
}

static inline void
instrument_get_proc_address_return(dcontext_t *dcontext, instrlist_t *ilist, instr_t *insert_before) {
    uint added_size = 0U;

    PRE(insert_before, added_size, INSTR_CREATE_push(dcontext,
        opnd_create_reg(DR_REG_XBX)));

    PRE(insert_before, added_size, RESTORE_FROM_TLS(dcontext, DR_REG_XBX, TLS_RESOLVED_IMPORTS));

    PRE(insert_before, added_size, INSTR_CREATE_mov_st(dcontext,
        OPND_CREATE_MEMPTR(DR_REG_XBX, sizeof(char*)),
        opnd_create_reg(DR_REG_XAX)));

    PRE(insert_before, added_size, INSTR_CREATE_add(dcontext,
        opnd_create_reg(DR_REG_XBX),
        OPND_CREATE_INT8(sizeof(resolved_import_t))));

    PRE(insert_before, added_size, SAVE_TO_TLS(dcontext, DR_REG_XBX, TLS_RESOLVED_IMPORTS));

    PRE(insert_before, added_size, INSTR_CREATE_pop(dcontext,
        opnd_create_reg(DR_REG_XBX)));
}
#endif
