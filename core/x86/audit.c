/* **********************************************************
 * Copyright (c) 2016 UCI PLRG.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "../globals.h"
#include "../fragment.h"
#include "../link.h"
#include "../module_shared.h"
#include "../monitor.h"
#include "../hashtable.h"
#include "instr.h"
#include "instr_create.h"
#include "instrument.h"
#include "audit.h"

#ifdef SECURITY_AUDIT /* around whole file */

audit_callbacks_t *audit_callbacks = NULL;

#define FRAME_RETURN_ADDRESS(bp) ((app_pc) *((bp)+1))

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

#define SAVE_TO_TLS(dc, reg, offs) \
    instr_create_save_to_tls(dc, reg, offs)

#define RESTORE_FROM_TLS(dc, reg, offs) \
    instr_create_restore_from_tls(dc, reg, offs)

/**** hashtablex header template ****/

/* Used by the hashtablex template to name the hashtable functions. */
#define NAME_KEY ibp // "ibp" = "indirect branch path"

/* The entry type is just key, no payload. */
#define ENTRY_TYPE bb_tag_pairing_t

/* End sentinel is <1,0>
 * No collisions in x32
 * Collision occurs in x64 on { mask32(to) == 1, (mask32(from) ^ (mask32(to) <<o 1)) == 0 }
 *     => { mask32(to) == 1, mask32(from) == 2 }
 *     (quite unlikely, though possible) */
#define IBP_HASHTABLE_END_SENTINEL ((bb_tag_pairing_t) 0x100000000)

/* none */
#define CUSTOM_FIELDS

#define DISABLE_STAT_STUDY 1
#define FAST_CLEAR 1

/* Request template header content. */
#define HASHTABLEX_HEADER 1
#include "../hashtablex.h" /*** invoke the template ***/
#undef HASHTABLEX_HEADER

/**** hashtablex.h template ****/

#define NAME_KEY ibp // "ibp" = "indirect branch path"

/* no payload, because we are only checking for existence */
#define TAG_TYPE bb_tag_pairing_t
#define ENTRY_TYPE bb_tag_pairing_t

#define ENTRY_TAG(f)              (f)
#define ENTRY_EMPTY               ((bb_tag_pairing_t) 0)

/* using 2 and forcing the match candidate to an odd number to avoid collisions */
#define ENTRY_SENTINEL            ((bb_tag_pairing_t) IBP_HASHTABLE_END_SENTINEL)

#define ENTRY_IS_EMPTY(f)         ((f) == ENTRY_EMPTY)
#define ENTRY_IS_SENTINEL(f)      ((f) == ENTRY_SENTINEL)

// cs-todo: make sure the VM stops all threads for this operation
/* transitory heap value `removing_tag` specifies the set of entries to remove */
#define ENTRY_IS_INVALID(f)       false

#define ENTRIES_ARE_EQUAL(t,f,g)    (f == g)
#define HASHTABLE_WHICH_HEAP(flags) (ACCT_CLIENT)
#define HTLOCK_RANK               table_rwlock
#define HASHTABLE_SUPPORT_PERSISTENCE 0
#define DISABLE_STAT_STUDY 1
#define FAST_CLEAR 1
#include "../hashtablex.h" /*** invoke the template ***/

/**** Private Fields ****/

#define GENERIC_ENTRY_IS_REAL(e) ((e) != 0 && (e) != (bb_tag_pairing_t) 2)

static const uint INITIAL_KEY_SIZE = 16;
static const uint LOAD_FACTOR_PERCENT = 80;
static const uint MASK_OFFSET = 0;

static ibp_table_t *ibp_table;

DR_API
void
dr_enter_fcache(dcontext_t *dcontext, app_pc tag)
{
    fcache_enter_func_t fcache_enter;
    fragment_t *f = fragment_lookup(dcontext, tag);

    if (TEST(FRAG_SHARED, f->flags))
        fcache_enter = get_fcache_enter_shared_routine(dcontext);
    else
        fcache_enter = get_fcache_enter_private_routine(dcontext);

    enter_fcache(dcontext, fcache_enter, FCACHE_ENTRY_PC(f));
}

DR_API
void
dr_register_audit_callbacks(audit_callbacks_t *callbacks)
{
    audit_callbacks = callbacks;
}

DR_API
app_pc
dcontext_get_next_tag(dcontext_t *dcontext)
{
    return dcontext->next_tag;
}

DR_API
byte *
dr_get_ntdll_proc_address(const char *name)
{
    return (byte *) get_proc_address(get_ntdll_base(), name);
}

DR_API
bool
dr_is_safe_to_read(byte *pc, size_t size)
{
    return is_readable_without_exception_query_os(pc, size);
}

DR_API
local_security_audit_state_t *
dcontext_get_audit_state(dcontext_t *dcontext)
{
    return &((local_state_extended_t *) dcontext->local_state)->security_audit_state;
}

DR_API
ibp_metadata_t *
dcontext_get_ibp_data(dcontext_t *dcontext)
{
    return &dcontext_get_audit_state(dcontext)->ibp_data;
}

DR_API
app_pc
dcontext_get_app_stack_pointer(dcontext_t *dcontext)
{
#ifdef X64
    return (app_pc) dcontext->upcontext_ptr->mcontext.rsp;
#else
    return (app_pc) dcontext->upcontext_ptr->mcontext.esp;
#endif
}

DR_API
app_pc
dr_get_building_trace_tail(dcontext_t *dcontext, bool *is_return, app_pc *trace_tag)
{
    if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit) &&
        is_building_trace(dcontext)) {
        monitor_data_t *md = (monitor_data_t *) dcontext->monitor_field;

        if (is_return != NULL)
            *is_return = TEST(LINK_RETURN, md->final_exit_flags);
        if (trace_tag != NULL)
            *trace_tag = md->trace_tag;

        return md->blk_info[md->num_blks-1].info.tag;
    } else {
        return NULL;
    }
}

DR_API
bool
dr_is_part_of_interception(app_pc tag)
{
    return is_part_of_interception(tag);
}

DR_API
byte
dr_fragment_find_direct_ordinal(fragment_t *from, app_pc to) {
    linkstub_t *l;
    byte exit_ordinal = 0x0;

    for (l = FRAGMENT_EXIT_STUBS(from); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (LINKSTUB_DIRECT(l->flags) && (((direct_linkstub_t*)l)->target_tag == to)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    SEC_LOG(4, "Could not find the correct exit ordinal for direct link from tag "PX"\n",
            from->tag);
    return 0xFF;
}

DR_API
byte
dr_fragment_lookup_direct_ordinal(dcontext_t *dcontext, app_pc from, app_pc to)
{
    fragment_t *from_f = fragment_lookup(dcontext, from);
    if (from_f == NULL)
        return UNKNOWN_ORDINAL;
    else
        return dr_fragment_find_direct_ordinal(from_f, to);
}

DR_API
byte
dr_fragment_find_indirect_ordinal(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (LINKSTUB_INDIRECT(l->flags)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    return 0xff;
}

DR_API
byte
dr_fragment_find_call_ordinal(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (TEST(LINK_CALL, l->flags)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    return 0xff;
}

DR_API
byte
dr_fragment_count_ordinals(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (!LINKSTUB_SPECIAL(l->flags))
            exit_ordinal++;
        if (TEST(LINK_CALL, l->flags))
            exit_ordinal++; // one more for the call continuation
    }

    return exit_ordinal;
}

DR_API
void
dr_fragment_log_ordinals(dcontext_t *dcontext, app_pc tag,
                         const char *line_prefix, uint loglevel)
{
    fragment_t *f = fragment_lookup(dcontext, tag);

    if (f != NULL) {
        linkstub_t *l;
        byte exit_ordinal = 0x0;

        for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l), exit_ordinal++) {
            if (LINKSTUB_DIRECT(l->flags)) {
                SEC_LOG(loglevel, "%s#%d to "PX" flags: 0x%x; cti offset: "PX"\n",
                        line_prefix, exit_ordinal, ((direct_linkstub_t*)l)->target_tag,
                        l->flags, l->cti_offset);
            } else {
                SEC_LOG(loglevel, "%s#%d flags: 0x%x; cti offset: "PX"\n", line_prefix,
                        exit_ordinal, l->flags, l->cti_offset);
            }
        }
    }
}

DR_API
void
dr_log_ibp_state(dcontext_t *dcontext, uint loglevel)
{
    ibp_metadata_t *ibp_data = dcontext_get_ibp_data(dcontext);
    fragment_t *from_f = fragment_lookup_bb(dcontext, ibp_data->ibp_from_tag);
    fragment_t *to_f = fragment_lookup_bb(dcontext, ibp_data->ibp_to_tag);
    fragment_t *last_f = linkstub_fragment(dcontext, dcontext->last_exit);
    if (from_f != NULL && to_f != NULL && last_f != NULL) {
        SEC_LOG(loglevel, PX" @"PX" -UR-> "PX" @"PX". Last fragment "PX" @"PX"\n",
                from_f->tag, from_f->start_pc, to_f->tag, to_f->start_pc,
                last_f->tag, last_f->start_pc);
    }
}

DR_API
void
dr_log_last_exit(dcontext_t *dcontext, app_pc tag, const char *prefix, uint loglevel)
{
    linkstub_t *l;
    fragment_t *f = fragment_lookup(dcontext, tag);

    SEC_LOG(loglevel, "%s%sbuilding trace\n", prefix,
            is_building_trace(dcontext) ? "" : "not ");

    if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit)) {
        dr_fragment_t *last_f = dcontext->last_fragment;
        dr_fragment_t *in_f = linkstub_fragment(dcontext, dcontext->last_exit);

        SEC_LOG(loglevel, "%sIndirect exit for %s %s: "PX".\n", prefix,
                last_f == NULL ? 0 : TEST(FRAG_IS_TRACE, last_f->flags) ? "trace" : "bb",
                TEST(LINK_RETURN, dcontext->last_exit->flags) ? "ret" :
                EXIT_IS_CALL(dcontext->last_exit->flags) ? "call*" : "jmp*",
                in_f == NULL ? (last_f == NULL ? 0 : last_f->tag) : in_f->tag);
    }

    for (l = f->in_xlate.incoming_stubs; l != NULL; l = LINKSTUB_NEXT_INCOMING(l)) {
        dr_fragment_t *in_f = linkstub_fragment(dcontext, l);
        SEC_LOG(loglevel, "%sFound a linkstub from "PX" with flags 0x%x\n", prefix,
                in_f->tag, l->flags);
    }
}

// cs-todo: put these back in the client
DR_API
void
dr_instrument_call_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *call_instr) {
    uint added_size = 0U;
    instr_t *stack_add = INSTR_CREATE_lea(dcontext,
        opnd_create_reg(DR_REG_XSI),
        opnd_create_base_disp(DR_REG_NULL, DR_REG_XSI, 1, sizeof(shadow_stack_frame_t), OPSZ_lea));

    PRE(call_instr, added_size, SAVE_TO_TLS(dcontext, DR_REG_XSI, TLS_XSI_TEMP));
    PRE(call_instr, added_size, RESTORE_FROM_TLS(dcontext, DR_REG_XSI, TLS_SHADOW_STACK_POINTER));

    PRE(call_instr, added_size, INSTR_CREATE_mov_imm(dcontext,
        OPND_CREATE_MEMPTR(DR_REG_XSI, 0),
        OPND_CREATE_INTPTR(instr_get_app_pc(call_instr) + instr_length(dcontext, call_instr))));

    PRE(call_instr, added_size, INSTR_CREATE_mov_st(dcontext,
        OPND_CREATE_MEMPTR(DR_REG_XSI, sizeof(app_pc)),
        opnd_create_reg(DR_REG_XSP)));

    PRE(call_instr, added_size, stack_add);

    PRE(call_instr, added_size, SAVE_TO_TLS(dcontext, DR_REG_XSI, TLS_SHADOW_STACK_POINTER));
    PRE(call_instr, added_size, RESTORE_FROM_TLS(dcontext, DR_REG_XSI, TLS_XSI_TEMP));
}

DR_API
uint
dr_instrument_return_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag) {
    uint added_size = 0U;
    instr_t *stack_sub = INSTR_CREATE_lea(dcontext,
        opnd_create_reg(DR_REG_XCX),
        opnd_create_base_disp(DR_REG_NULL, DR_REG_XCX, 1, -(int)sizeof(shadow_stack_frame_t), OPSZ_lea));

    // lea ecx, [TLS_SHADOW_STACK_POINTER-8] - <singleton-return-address>
    // jecxz next
    PRE(next, added_size, RESTORE_FROM_TLS(dcontext, DR_REG_XCX, TLS_SHADOW_STACK_POINTER));
    PRE(next, added_size, stack_sub);
    PRE(next, added_size, SAVE_TO_TLS(dcontext, DR_REG_XCX, TLS_SHADOW_STACK_POINTER));
    return added_size;
}

DR_API
bb_tag_pairing_t
dr_ibp_lookup(dcontext_t *dcontext, bb_tag_pairing_t key)
{
    bb_tag_pairing_t value;

    TABLE_RWLOCK(ibp_table, read, lock);
    value = hashtable_ibp_lookup(dcontext, key, ibp_table);
    TABLE_RWLOCK(ibp_table, read, unlock);

    return value;
}

DR_API
void
dr_ibp_add(dcontext_t *dcontext, bb_tag_pairing_t value)
{
    TABLE_RWLOCK(ibp_table, write, lock);
    hashtable_ibp_add(dcontext, value, ibp_table);
    TABLE_RWLOCK(ibp_table, write, unlock);
}

DR_API
bool
dr_ibp_add_new(dcontext_t *dcontext, bb_tag_pairing_t possibly_new)
{
    bool added = false;
    bb_tag_pairing_t value;

    TABLE_RWLOCK(ibp_table, write, lock);
    value = hashtable_ibp_lookup(dcontext, possibly_new, ibp_table);
    if (value == 0ULL) {
        hashtable_ibp_add(dcontext, possibly_new, ibp_table);
        added = true;
    }
    TABLE_RWLOCK(ibp_table, write, unlock);
    return added;
}

DR_API
bb_tag_pairing_t *
dr_ibp_lookup_for_removal(bb_tag_pairing_t key, uint *index)
{
    return NULL;
}

DR_API
bool
dr_ibp_remove(bb_tag_pairing_t value)
{
    bool removed;

    TABLE_RWLOCK(ibp_table, write, lock);
    removed = hashtable_ibp_remove(value, ibp_table);
    TABLE_RWLOCK(ibp_table, write, unlock);

    return removed;
}

DR_API
bool
dr_ibp_remove_helper(uint hindex, bb_tag_pairing_t *previous)
{
    return false;
}

DR_API
void
dr_ibp_clear(dcontext_t *dcontext)
{
    TABLE_RWLOCK(ibp_table, write, lock);
    hashtable_ibp_clear(dcontext, ibp_table);
    TABLE_RWLOCK(ibp_table, write, unlock);
}

DR_API
opnd_t
dr_create_audit_tls_slot(ushort offset)
{
    return opnd_create_tls_slot(os_tls_offset(offset));
}

DR_API
instr_t *
dr_create_save_to_audit_tls(dcontext_t *dcontext, reg_id_t reg, ushort offset)
{
    return instr_create_save_to_tls(dcontext, reg, offset);
}

DR_API
instr_t *
dr_create_restore_from_audit_tls(dcontext_t *dcontext, reg_id_t reg, ushort offset)
{
    return instr_create_restore_from_tls(dcontext, reg, offset);
}

DR_API
bool
dr_is_disp_audit_tls(opnd_t opnd, ushort offset)
{
    return opnd_get_disp(opnd) == os_tls_offset(offset);
}

DR_API
void
dr_lock_modules()
{
    dynamo_vm_areas_lock();
}

DR_API
void
dr_unlock_modules()
{
    dynamo_vm_areas_unlock();
}

DR_API
IMAGE_EXPORT_DIRECTORY *
dr_get_module_exports_directory(app_pc base_addr,
                                OUT size_t *exports_size /* may be NULL */
                                _IF_NOT_X64(bool ldr64))
{
    return get_module_exports_directory_common(base_addr, exports_size, ldr64);
}

DR_API
bool
dr_is_dll_entry_callback(app_pc tag)
{
    extern app_pc ldrpCallInitRoutine_address_NT;
    return tag == ldrpCallInitRoutine_address_NT;
}

/**** need this???
/ * pass 0 to start.  returns -1 when there are no more entries. * /
int
ibp_hash_iterate_next(dcontext_t *dcontext, ibp_table_t *htable, int iter,
                          OUT bb_tag_pairing_t *key) {
    int i;
    bb_tag_pairing_t e = 0;
    for (i = iter; i < (int) htable->capacity; i++) {
        e = htable->table[i];
        if (!GENERIC_ENTRY_IS_REAL(e))
            continue;
        else
            break;
    }
    if (i >= (int) htable->capacity)
        return -1;
    ASSERT(e != 0);
    if (key != 0)
        *key = e;
    return i+1;
}

int
ibp_hash_iterate_remove(dcontext_t *dcontext, ibp_table_t *htable, int iter,
                            bb_tag_pairing_t key) {
    bb_tag_pairing_t e;
    uint hindex;
    bb_tag_pairing_t *rm;
    int res = iter;

    e = hashtable_ibp_lookup(dcontext, key, htable);
    rm = hashtable_ibp_lookup_for_removal(e, htable, &hindex);
    if (rm != NULL) {
        if (hashtable_ibp_remove_helper(htable, hindex, rm)) {
            / * pulled entry from start to here so skip it as we've already seen it * /
        } else {
            / * pulled entry from below us, so step back * /
            res--;
        }
        hashtable_ibp_free_entry(dcontext, htable, e);
    }
    return res;
}
*/

/****************************************************************************
 * CORE INTEGRATION
 */

typedef struct _audit_thread_list_t {
    uint thread_count;
    uint capacity;
    uint empty_slots;
    dcontext_t **threads;
} audit_thread_list_t;

static audit_thread_list_t *threads;  /* synchronized under ibp_table_t's TABLE_RWLOCK */

static void
audit_thread_append(dcontext_t *thread)
{
    if (threads->thread_count == threads->capacity) {
        uint old_capacity = threads->capacity;
        dcontext_t **new_threads;

        threads->capacity *= 2;
        new_threads = dr_global_alloc(threads->capacity * sizeof(dcontext_t *));
        memcpy(new_threads, threads, old_capacity * sizeof(dcontext_t *));
        dr_global_free(threads->threads, old_capacity * sizeof(dcontext_t *));
        threads->threads = new_threads;
    }

    if (threads->empty_slots > 0) {
        uint i, end = threads->thread_count + threads->empty_slots;

        for (i = 0; i < end; i++) {
            if (threads->threads[i] == NULL)
                threads->threads[i] = thread;
        }
        threads->empty_slots--;
    } else {
        threads->threads[threads->thread_count++] = thread;
    }
    threads->thread_count++;
}

static void
audit_thread_remove(dcontext_t *thread)
{
    uint i, end = threads->thread_count + threads->empty_slots;

    for (i = 0; i < end; i++) {
        if (threads->threads[i] == thread) {
            threads->threads[i] = NULL;
            break;
        }
    }
    threads->thread_count--;
    threads->empty_slots++;
}

void
audit_init()
{
    uint flags = 0UL;

    threads = dr_global_alloc(sizeof(audit_thread_list_t));
    memset(threads, 0, sizeof(audit_thread_list_t));
    threads->capacity = 0x20;
    threads->threads = dr_global_alloc(threads->capacity * sizeof(dcontext_t *));

    ibp_table = (ibp_table_t*) dr_global_alloc(sizeof(ibp_table_t));
    flags |= HASHTABLE_PERSISTENT;
    flags |= HASHTABLE_ENTRY_SHARED;
    flags |= HASHTABLE_SHARED;
    flags |= HASHTABLE_RELAX_CLUSTER_CHECKS;
    flags |= HASHTABLE_NOT_PRIMARY_STORAGE;
    hashtable_ibp_init(GLOBAL_DCONTEXT,
        ibp_table,
        INITIAL_KEY_SIZE,
        LOAD_FACTOR_PERCENT,
        HASH_FUNCTION_NONE,
        MASK_OFFSET,
        flags
        _IF_DEBUG("ibp table"));

    SEC_LOG(3, "Allocated IBP table at "PX"\n", ibp_table);
}

void
audit_exit()
{
    dr_global_free(threads->threads, threads->capacity * sizeof(dcontext_t *));
    dr_global_free(threads, sizeof(audit_thread_list_t));
    threads = NULL;

    hashtable_ibp_free(GLOBAL_DCONTEXT, ibp_table);
    dr_global_free(ibp_table, sizeof(ibp_table_t));
}

void
audit_thread_init(dcontext_t *dcontext)
{
    local_security_audit_state_t *csd = dcontext_get_audit_state(dcontext);

    ASSERT(csd != NULL);

    csd->ibp_data.lookuptable = ibp_table->table;
    csd->ibp_data.hash_mask = ibp_table->hash_mask;

    TABLE_RWLOCK(ibp_table, write, lock);
    audit_thread_append(dcontext);
    TABLE_RWLOCK(ibp_table, write, unlock);

    audit_client_thread_init(dcontext);
}

void
audit_thread_exit(dcontext_t *dcontext)
{
    if (threads == NULL)
        return;

    TABLE_RWLOCK(ibp_table, write, lock);
    audit_thread_remove(dcontext);
    TABLE_RWLOCK(ibp_table, write, unlock);

    audit_client_thread_exit(dcontext);
}

static inline void
update_ibp_table_and_mask(dcontext_t *dcontext, ibp_table_t *htable) {
    uint i, end = threads->thread_count + threads->empty_slots;
    local_security_audit_state_t *csd;

    for (i = 0; i < end; i++) {
        if (threads->threads[i] != NULL) {
            csd = dcontext_get_audit_state((dcontext_t *) threads->threads[i]);
            csd->ibp_data.lookuptable = htable->table;
            csd->ibp_data.hash_mask = htable->hash_mask;
        }
    }

    SEC_LOG(3, "ibp update on thread 0x%x: table is now at "PX" with mask %x\n",
            dr_get_thread_id(dcontext), htable->table, htable->hash_mask);
}

static void
hashtable_ibp_init_internal_custom(dcontext_t *dcontext, ibp_table_t *htable) {
    update_ibp_table_and_mask(dcontext, htable);
}

static void
hashtable_ibp_resized_custom(dcontext_t *dcontext, ibp_table_t *htable,
                                uint old_capacity, bb_tag_pairing_t *old_table,
                                bb_tag_pairing_t *old_table_unaligned,
                                uint old_ref_count, uint old_table_flags) {
    update_ibp_table_and_mask(dcontext, htable);
}

static void
hashtable_ibp_free_entry(dcontext_t *dcontext, ibp_table_t *table, bb_tag_pairing_t tag)
{
    /*nothing*/
}

#ifdef DEBUG
static void
hashtable_ibp_study_custom(dcontext_t *dcontext, ibp_table_t *htable, uint inc)
{
    /*none*/
}
#endif /* DEBUG */

#endif /* SECURITY_AUDIT */
