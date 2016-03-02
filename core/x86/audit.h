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

#ifndef _AUDIT_H_
#define _AUDIT_H_ 1

#include "../globals.h"
#include "../fragment.h"
#include "../synch.h"
#include "instr.h"

#ifdef WINDOWS
# include "../win32/ntdll_types.h"
#endif

/* DR_API EXPORT TOFILE dr_audit.h */
/* DR_API EXPORT BEGIN */

#ifdef SECURITY_AUDIT

#define SEC_LOG(level, format, ...) \
do { \
    if (audit_callbacks != NULL && audit_callbacks->loglevel >= level) \
        dr_fprintf(*audit_callbacks->audit_log_file, format, __VA_ARGS__); \
} while (0)

/* for the pairing of two BB tags */
typedef uint64 bb_tag_pairing_t;

#endif /* SECURITY_AUDIT */

#ifdef API_EXPORT_ONLY
#include "dr_config.h"

typedef void dcontext_t;

typedef struct _dr_fragment_t {
    app_pc    tag;
    uint      flags;
} dr_fragment_t;
#endif /* API_EXPORT_ONLY */

/* DR_API EXPORT END */

typedef fragment_t dr_fragment_t; /* not API exported */

/* DR_API EXPORT TOFILE dr_audit.h */
/* DR_API EXPORT BEGIN */

#ifdef SECURITY_AUDIT

#ifdef X64
# define SHADOW_STACK_SENTINEL 0ULL
# define SHADOW_STACK_EMPTY_TAG 0xf0f0f0f0f0f0f0f0ULL
# define SHADOW_STACK_CALLBACK_TAG 0xc0c0c0c0c0c0c0c0ULL
#else
# define SHADOW_STACK_SENTINEL 0UL
# define SHADOW_STACK_EMPTY_TAG 0xf0f0f0f0UL
# define SHADOW_STACK_CALLBACK_TAG 0xc0c0c0c0UL
#endif

// cs-todo: read app max from PE optional header SizeOfStackReserve @72
#define SHADOW_STACK_SIZE 0x200 // in frames

#define SHADOW_FRAME(sas) (sas->shadow_stack-1)
#define SHADOW_PEEK(sas, n) (sas->shadow_stack-(n+1))
#define IS_CALLBACK_FRAME(sas) \
    ((SHADOW_FRAME(sas)->base_pointer == (app_pc)SHADOW_STACK_SENTINEL) && \
     (SHADOW_FRAME(sas)->return_address == (app_pc)SHADOW_STACK_CALLBACK_TAG))

#define UNKNOWN_ORDINAL 0xff

/****************************************************************************
 * SECURITY AUDITING SUPPORT
 */

typedef struct _audit_callbacks_t {
    file_t *audit_log_file;
    uint loglevel;
    void (*audit_init)(dcontext_t *dcontext, bool is_fork);
    void (*audit_exit)();
    void (*audit_init_log)(bool is_fork, bool is_wow64_process);
    file_t (*audit_create_logfile)();
    void (*audit_dynamo_model_initialized)();
    void (*audit_thread_init)(dcontext_t *dcontext);
    void (*audit_thread_exit)(dcontext_t *dcontext);
    void (*audit_process_fork)(dcontext_t *dcontext, const wchar_t *name);
    void (*audit_process_terminating)(bool external, bool is_crash, const char *file,
                                      int line, const char *expr);
    void (*audit_dispatch)(dcontext_t *dcontext);
    void (*audit_fcache_enter)(dcontext_t *dcontext);
    void (*audit_fragment_direct_link)(dcontext_t *dcontext, app_pc from,
                                       app_pc to, byte ordinal);
    void (*audit_fragment_indirect_link)(dcontext_t *dcontext);
    void (*audit_syscall)(dcontext_t *dcontext, app_pc tag,
                          int sysnum, bool is_executable_alloc);
    bool (*audit_filter_syscall)(int sysnum);
    void (*audit_bb_link_complete)(dcontext_t *dcontext, app_pc tag);
    void (*audit_translation)(dcontext_t *dcontext, app_pc start_pc, instrlist_t *ilist,
                              int sysnum);
    void (*audit_fragment_remove)(dcontext_t *dcontext, app_pc tag);
    void (*audit_cache_reset)(dcontext_t *dcontext);
    void (*audit_memory_executable_change)(dcontext_t *dcontext, app_pc base, size_t size,
                                           bool becomes_executable, bool safe_to_read);
    void (*audit_code_area_expansion)(app_pc original_start, app_pc original_end,
                                      app_pc new_start, app_pc new_end,
                                      bool is_dynamo_areas);
    void (*audit_code_area)(dcontext_t *dcontext, app_pc start, app_pc end, bool created);
    uint (*audit_indirect_branchpoint)(dcontext_t *dcontext, instrlist_t *ilist,
                                       app_pc tag, instr_t *ibl_instr, bool is_return,
                                       int syscall_number);
    uint (*audit_return)(dcontext_t *dcontext, instrlist_t *ilist,
                         instr_t *next, app_pc tag);
    void (*audit_gencode_phase)(bool start);
    void (*audit_instr)(instr_t *instr, byte *copy_pc);
    void (*audit_instrument_ibl_indirect_handler)(dcontext_t *dcontext,
                                                  instrlist_t *ilist,
                                                  app_pc ibl_routine_start_pc,
                                                  instr_t *fragment_not_found_handler);
    void (*audit_instrument_ibl_indirect_hook)(dcontext_t *dcontext, instrlist_t *ilist,
                                               app_pc ibl_routine_start_pc);
    void (*audit_instrument_ibl_fcache_return)(dcontext_t *dcontext, instrlist_t *ilist,
                                               app_pc ibl_routine_start_pc);
    app_pc (*audit_adjust_for_ibl_instrumentation)(dcontext_t *dcontext, app_pc pc,
                                                   app_pc raw_start_pc);
    void (*audit_code_modification)(dcontext_t *dcontext, dr_fragment_t *f, app_pc next_pc,
                                    app_pc target, size_t write_size);
    void (*audit_gencode_ibl_routine)(app_pc pc, bool syscall);
    void (*audit_heartbeat)(dcontext_t *dcontext);
    void (*audit_intercept)(app_pc start, app_pc end);
    void (*audit_callback_context_switch)(dcontext_t *dcontext, bool is_return);
    void (*audit_nested_shadow_stack)(dcontext_t *dcontext, bool push);
    void (*audit_nt_continue)(dcontext_t *dcontext);
    void (*audit_socket_handle)(dcontext_t *dcontext, HANDLE handle, bool created);
    void (*audit_device_io_control)(dcontext_t *dcontext, uint result, HANDLE socket,
                                    HANDLE event, IO_STATUS_BLOCK *status_block,
                                    IoControlCode control_code, byte *input_data,
                                    uint input_length, byte *output_data,
                                    uint output_length);
    void (*audit_wait_for_single_object)(dcontext_t *dcontext, HANDLE event);
    void (*audit_wait_for_multiple_objects)(dcontext_t *dcontext, uint result,
                                            uint handle_count, HANDLE *handles,
                                            bool wait_all);
} audit_callbacks_t;

extern audit_callbacks_t *audit_callbacks;

/* DR_API EXPORT END */

DR_API
void
dr_enter_fcache(dcontext_t *dcontext, app_pc tag);

DR_API
void
dr_register_audit_callbacks(audit_callbacks_t *callbacks);

DR_API
app_pc
dcontext_get_next_tag(dcontext_t *dcontext);

DR_API
byte *
dr_get_ntdll_proc_address(const char *name);

DR_API
bool
dr_is_safe_to_read(byte *pc, size_t size);

DR_API
ibp_metadata_t *
dcontext_get_ibp_data(dcontext_t *dcontext);

DR_API
app_pc
dcontext_get_app_stack_pointer(dcontext_t *dcontext);

DR_API
local_security_audit_state_t *
dcontext_get_audit_state(dcontext_t *dcontext);

DR_API
app_pc
dr_get_building_trace_tail(dcontext_t *dcontext, bool *is_return, app_pc *trace_tag);

DR_API
bool
dr_is_part_of_interception(app_pc tag);

DR_API
byte
dr_fragment_find_direct_ordinal(dr_fragment_t *from, app_pc to);

DR_API
byte
dr_fragment_lookup_direct_ordinal(dcontext_t *dcontext, app_pc from, app_pc to);

DR_API
byte
dr_fragment_find_indirect_ordinal(dr_fragment_t *f);

DR_API
byte
dr_fragment_find_call_ordinal(dr_fragment_t *f);

DR_API
byte
dr_fragment_count_ordinals(dr_fragment_t *f);

DR_API
void
dr_fragment_log_ordinals(dcontext_t *dcontext, app_pc tag,
                         const char *line_prefix, uint loglevel);

DR_API
void
dr_log_ibp_state(dcontext_t *dcontext, uint loglevel);

DR_API
void
dr_log_last_exit(dcontext_t *dcontext, app_pc tag, const char *prefix, uint loglevel);

DR_API
void
dr_instrument_call_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *call_instr);

DR_API
uint
dr_instrument_return_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag);

DR_API
bb_tag_pairing_t
dr_ibp_lookup(dcontext_t *dcontext, bb_tag_pairing_t key);

DR_API
bb_tag_pairing_t *
dr_ibp_lookup_for_removal(bb_tag_pairing_t key, uint *index);

DR_API
void
dr_ibp_add(dcontext_t *dcontext, bb_tag_pairing_t value);

DR_API
bool
dr_ibp_add_new(dcontext_t *dcontext, bb_tag_pairing_t possibly_new);

DR_API
bool
dr_ibp_remove(bb_tag_pairing_t value);

DR_API
bool
dr_ibp_remove_helper(uint hindex, bb_tag_pairing_t *previous);

DR_API
void
dr_ibp_clear(dcontext_t *dcontext);

DR_API
opnd_t
dr_create_audit_tls_slot(ushort offset);

DR_API
instr_t *
dr_create_save_to_audit_tls(dcontext_t *dcontext, reg_id_t reg, ushort offset);

DR_API
instr_t *
dr_create_restore_from_audit_tls(dcontext_t *dcontext, reg_id_t reg, ushort offset);

DR_API
bool
dr_is_disp_audit_tls(opnd_t opnd, ushort offset);

DR_API
void
dr_lock_modules();

DR_API
void
dr_unlock_modules();

DR_API
IMAGE_EXPORT_DIRECTORY *
dr_get_module_exports_directory(app_pc base_addr,
                                OUT size_t *exports_size /* may be NULL */
                                _IF_NOT_X64(bool ldr64));

DR_API
bool
dr_is_dll_entry_callback(app_pc tag);

/****************************************************************************
 * CORE INTEGRATION
 */

void
audit_init();

void
audit_exit();

void
audit_thread_init(dcontext_t *dcontext);

void
audit_thread_exit(dcontext_t *dcontext);

/****************************************************************************
 * SECURITY AUDITING INTERNAL_CALLBACKS
 */

/* global process state */

inline void
audit_client_init(dcontext_t *dcontext, bool is_fork)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_init(dcontext, is_fork);
}

inline void
audit_client_exit()
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_exit();
}

inline void
audit_init_log(bool is_fork, bool is_wow64_process)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_init_log(is_fork, is_wow64_process);
}

inline file_t
audit_create_logfile()
{
    if (audit_callbacks == NULL)
        return INVALID_FILE;

    return audit_callbacks->audit_create_logfile();
}

inline void
audit_dynamo_model_initialized()
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_dynamo_model_initialized();
}

inline void
audit_client_thread_init(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_thread_init(dcontext);
}

inline void
audit_client_thread_exit(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_thread_exit(dcontext);
}

inline void
audit_process_fork(dcontext_t *dcontext, const wchar_t *name)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_process_fork(dcontext, name);
}

inline void
audit_process_terminating(bool external, bool is_crash, const char *file,
                          int line, const char *expr)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_process_terminating(external, is_crash, file, line, expr);
}

/* dispatch */

inline void
audit_dispatch(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_dispatch(dcontext);
}

inline void
audit_fcache_enter(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_fcache_enter(dcontext);
}

/* links */

inline void
audit_fragment_direct_link(dcontext_t *dcontext, app_pc from, app_pc to, byte ordinal)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_fragment_direct_link(dcontext, from, to, ordinal);
}

inline void
audit_fragment_indirect_link(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_fragment_indirect_link(dcontext);
}

inline void
audit_syscall(dcontext_t *dcontext, app_pc tag, int sysnum, bool is_executable_alloc)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_syscall(dcontext, tag, sysnum, is_executable_alloc);
}

inline bool
audit_filter_syscall(int sysnum)
{
    if (audit_callbacks == NULL)
        return false/*ignore all sysnums*/;

    return audit_callbacks->audit_filter_syscall(sysnum);
}

inline void
audit_bb_link_complete(dcontext_t *dcontext, app_pc tag)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_bb_link_complete(dcontext, tag);
}

/* fragments */

inline void
audit_translation(dcontext_t *dcontext, app_pc start_pc, instrlist_t *ilist, int sysnum)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_translation(dcontext, start_pc, ilist, sysnum);
}

inline void
audit_fragment_remove(dcontext_t *dcontext, app_pc tag)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_fragment_remove(dcontext, tag);
}

inline void
audit_cache_reset(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_cache_reset(dcontext);
}

/* dgc */

inline void
audit_memory_executable_change(dcontext_t *dcontext, app_pc base, size_t size,
                               bool becomes_executable, bool safe_to_read)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_memory_executable_change(dcontext, base, size,
                                                    becomes_executable, safe_to_read);
}

inline void
audit_code_area_expansion(app_pc original_start, app_pc original_end, app_pc new_start,
                          app_pc new_end, bool is_dynamo_areas)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_code_area_expansion(original_start, original_end, new_start,
                                               new_end, is_dynamo_areas);
}

inline void
audit_code_area(dcontext_t *dcontext, app_pc start, app_pc end, bool created)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_code_area(dcontext, start, end, created);
}

/* ibl setup */

inline uint
audit_indirect_branchpoint(dcontext_t *dcontext, instrlist_t *ilist, app_pc tag,
                           instr_t *ibl_instr, bool is_return, int syscall_number)
{
    if (audit_callbacks == NULL)
        return 0;

    return audit_callbacks->audit_indirect_branchpoint(dcontext, ilist, tag, ibl_instr,
                                                       is_return, syscall_number);
}

inline uint
audit_return(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag)
{
    if (audit_callbacks == NULL)
        return 0;

    return audit_callbacks->audit_return(dcontext, ilist, next, tag);
}

/* ibl gencode */

inline void
audit_gencode_phase(bool start)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_gencode_phase(start);
}

inline void
audit_instr(instr_t *instr, byte *copy_pc)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_instr(instr, copy_pc);
}

inline void
audit_instrument_ibl_indirect_handler(dcontext_t *dcontext, instrlist_t *ilist,
                                      app_pc ibl_routine_start_pc,
                                      instr_t *fragment_not_found_handler)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_instrument_ibl_indirect_handler(dcontext, ilist,
                                                           ibl_routine_start_pc,
                                                           fragment_not_found_handler);
}

inline void
audit_instrument_ibl_indirect_hook(dcontext_t *dcontext, instrlist_t *ilist,
                                   app_pc ibl_routine_start_pc)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_instrument_ibl_indirect_hook(dcontext, ilist,
                                                        ibl_routine_start_pc);
}

inline void
audit_instrument_ibl_fcache_return(dcontext_t *dcontext, instrlist_t *ilist,
                                   app_pc ibl_routine_start_pc)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_instrument_ibl_fcache_return(dcontext, ilist,
                                                        ibl_routine_start_pc);
}

inline app_pc
audit_adjust_for_ibl_instrumentation(dcontext_t *dcontext, app_pc pc, app_pc raw_start_pc)
{
    if (audit_callbacks == NULL)
        return pc;

    return audit_callbacks->audit_adjust_for_ibl_instrumentation(dcontext, pc,
                                                                 raw_start_pc);
}

inline void
audit_code_modification(dcontext_t *dcontext, dr_fragment_t *f, app_pc next_pc,
                        app_pc target, size_t write_size)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_code_modification(dcontext, f, next_pc, target, write_size);
}

inline void
audit_gencode_ibl_routine(app_pc pc, bool syscall)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_gencode_ibl_routine(pc, syscall);
}

/* miscellaneous */

inline void
audit_heartbeat(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_heartbeat(dcontext);
}

inline void
audit_intercept(app_pc start, app_pc end)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_intercept(start, end);
}

#ifdef WINDOWS

/* callbacks */

inline void
audit_callback_context_switch(dcontext_t *dcontext, bool is_return)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_callback_context_switch(dcontext, is_return);
}

inline void
audit_nested_shadow_stack(dcontext_t *dcontext, bool push)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_nested_shadow_stack(dcontext, push);
}

inline void
audit_nt_continue(dcontext_t *dcontext)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_nt_continue(dcontext);
}

/* network */

inline void
audit_socket_handle(dcontext_t *dcontext, HANDLE handle, bool created)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_socket_handle(dcontext, handle, created);
}

inline void
audit_device_io_control(dcontext_t *dcontext, uint result, HANDLE socket, HANDLE event,
                        IO_STATUS_BLOCK *status_block, IoControlCode control_code,
                        byte *input_data, uint input_length,
                        byte *output_data, uint output_length)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_device_io_control(dcontext, result, socket, event,
                                             status_block, control_code, input_data,
                                             input_length, output_data, output_length);
}

inline void
audit_wait_for_single_object(dcontext_t *dcontext, HANDLE event)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_wait_for_single_object(dcontext, event);
}

inline void
audit_wait_for_multiple_objects(dcontext_t *dcontext, uint result, uint handle_count,
                                HANDLE *handles, bool wait_all)
{
    if (audit_callbacks == NULL)
        return;

    audit_callbacks->audit_wait_for_multiple_objects(dcontext, result, handle_count,
                                                     handles, wait_all);
}
#endif /* WINDOWS */

#else /* SECURITY_AUDIT */
# define SEC_LOG(level, ...)
#endif /* SECURITY_AUDIT */

#endif
