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

#ifdef SECURITY_AUDIT /* around whole file */

#include "../globals.h"
#include "instr.h"

#ifdef WINDOWS
# include "../win32/ntdll_types.h"
#endif

/* DR_API EXPORT TOFILE dr_audit.h */
/* DR_API EXPORT BEGIN */

/****************************************************************************
 * SECURITY AUDITING SUPPORT
 */

typedef struct _audit_callbacks_t {
    void (*audit_init)(dcontext_t *dcontext, bool is_fork);
    void (*audit_exit)();
    void (*audit_init_log)(bool is_fork);
    void (*audit_create_logfile)();
    void (*audit_close_logfile)();
    void (*audit_dynamo_model_initialized)();
    void (*audit_thread_init)(dcontext_t *dcontext);
    void (*audit_thread_exit)(dcontext_t *dcontext);
    void (*audit_process_fork)(dcontext_t *dcontext, const char *name);
    void (*audit_all_threads_synched)(thread_synch_state_t desired_synch_state,
                                      thread_synch_state_t cur_state);
    void (*audit_process_terminating)(bool external, bool is_crash, const char *file,
                                      int line, const char *expr);
    void (*audit_dispatch)(dcontext_t *dcontext);
    void (*audit_fcache_enter)(dcontext_t *dcontext);
    void (*audit_fragment_link)(dcontext_t *dcontext, bool direct, byte exit_ordinal);
    void (*audit_fragment_link_tags)(dcontext_t *dcontext, app_pc from_tag,
                                     app_pc to_tag, byte exit_ordinal);
    void (*audit_syscall)(ptr_uint_t sysnum);
    void (*audit_bb_link_complete)(dcontext_t *dcontext, fragment_t *f);
    void (*audit_translation)(dcontext_t *dcontext, app_pc start_pc, instrlist_t *ilist,
                              int sysnum);
    void (*audit_fragment_remove)(dcontext_t *dcontext, fragment_t *f);
    void (*audit_cache_reset)(dcontext_t *dcontext);
    void (*audit_memory_executable_change)(dcontext_t *dcontext, app_pc base, size_t size,
                                           bool becomes_executable, bool safe_to_read);
    void (*audit_code_area_expansion)(app_pc original_start, app_pc original_end,
                                      app_pc new_start, app_pc new_end,
                                      bool is_dynamo_areas);
    void (*audit_code_area)(dcontext_t *dcontext, app_pc start, app_pc end, bool created);
    void (*audit_indirect_branchpoint)(dcontext_t *dcontext, instrlist_t *ilist,
                                       app_pc tag, instr_t *ibl_instr, bool is_return,
                                       int syscall_number);
    void (*audit_return)(dcontext_t *dcontext, instrlist_t *ilist,
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
    void (*audit_code_modification)(dcontext_t *dcontext, fragment_t *f, app_pc next_pc,
                                    app_pc target, size_t write_size);
    void (*audit_gencode_ibl_routine)(app_pc pc, bool syscall);
    void (*audit_heartbeat)(dcontext_t *dcontext);
    void (*audit_intercept)(app_pc start, app_pc end);
    void (*audit_callback_context_switch)(dcontext_t *dcontext, bool is_return);
    void (*audit_nested_shadow_stack)(dcontext_t *dcontext, bool push);
    void (*audit_nt_continue)();
    void (*audit_socket_handle)(dcontext_t dcontext, HANDLE handle, bool created);
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

/* DR_API EXPORT END */

static void
audit_noop();

static audit_callbacks_t default_audit_callbacks = {
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
};

static audit_callbacks_t *audit_callbacks = &default_audit_callbacks;

DR_API
void
dr_enter_fcache(dcontext_t *dcontext, fcache_enter_func_t entry, cache_pc pc);

DR_API
void
dr_register_audit_callbacks(audit_callbacks_t *callbacks)
{
    audit_callbacks = callbacks;
}

/****************************************************************************
 * SECURITY AUDITING INTERNAL_CALLBACKS
 */

/* global process state */

inline void
audit_init(dcontext_t *dcontext, bool is_fork)
{
    audit_callbacks->audit_init(dcontext, is_fork);
}

inline void
audit_exit()
{
    audit_callbacks->audit_exit();
}

inline void
audit_init_log(bool is_fork)
{
    audit_callbacks->audit_init_log(is_fork);
}

inline file_t
audit_create_logfile()
{
    audit_callbacks->audit_create_logfile();
}

inline void
audit_close_logfile()
{
    audit_callbacks->audit_close_logfile();
}

inline void
audit_dynamo_model_initialized()
{
    audit_callbacks->audit_dynamo_model_initialized();
}

inline void
audit_thread_init(dcontext_t *dcontext)
{
    audit_callbacks->audit_thread_init(dcontext);
}

inline void
audit_thread_exit(dcontext_t *dcontext)
{
    audit_callbacks->audit_thread_exit(dcontext);
}

inline void
audit_process_fork(dcontext_t *dcontext, const char *name)
{
    audit_callbacks->audit_process_fork(dcontext, name);
}

inline void
audit_all_threads_synched(thread_synch_state_t desired_synch_state,
                          thread_synch_state_t cur_state)
{
    audit_callbacks->audit_all_threads_synched(desired_synch_state, cur_state);
}

inline void
audit_process_terminating(bool external, bool is_crash, const char *file,
                          int line, const char *expr)
{
    audit_callbacks->audit_process_terminating(external, is_crash, file, line, expr);
}

/* dispatch */

inline void
audit_dispatch(dcontext_t *dcontext)
{
    audit_callbacks->audit_dispatch(dcontext);
}

inline void
audit_fcache_enter(dcontext_t *dcontext)
{
    audit_callbacks->audit_fcache_enter(dcontext);
}

/* links */

inline void
audit_fragment_link(dcontext_t *dcontext, bool direct, byte exit_ordinal)
{
    audit_callbacks->audit_fragment_link(dcontext, direct, exit_ordinal);
}

inline void
audit_fragment_link_tags(dcontext_t *dcontext, app_pc from_tag, app_pc to_tag,
                         byte exit_ordinal)
{
    audit_callbacks->audit_fragment_link_tags(dcontext, from_tag, to_tag, exit_ordinal);
}

inline void
audit_syscall(ptr_uint_t sysnum)
{
    audit_callbacks->audit_syscall(sysnum);
}

inline void
audit_bb_link_complete(dcontext_t *dcontext, fragment_t *f)
{
    audit_callbacks->audit_bb_link_complete(dcontext, f);
}

/* fragments */

inline void
audit_translation(dcontext_t *dcontext, app_pc start_pc, instrlist_t *ilist, int sysnum)
{
    audit_callbacks->audit_translation(dcontext, start_pc, ilist, sysnum);
}

inline void
audit_fragment_remove(dcontext_t *dcontext, fragment_t *f)
{
    audit_callbacks->audit_fragment_remove(dcontext, f);
}

inline void
audit_cache_reset(dcontext_t *dcontext)
{
    audit_callbacks->audit_cache_reset(dcontext);
}

/* dgc */

inline void
audit_memory_executable_change(dcontext_t *dcontext, app_pc base, size_t size,
                               bool becomes_executable, bool safe_to_read)
{
    audit_callbacks->audit_memory_executable_change(dcontext, base, size,
                                                    becomes_executable, safe_to_read);
}

inline void
audit_code_area_expansion(app_pc original_start, app_pc original_end, app_pc new_start,
                          app_pc new_end, bool is_dynamo_areas)
{
    audit_callbacks->audit_code_area_expansion(original_start, original_end, new_start,
                                               new_end, is_dynamo_areas);
}

inline void
audit_code_area(dcontext_t *dcontext, app_pc start, app_pc end, bool created)
{
    audit_callbacks->audit_code_area(dcontext, start, end, created);
}

/* ibl setup */

inline uint
audit_indirect_branchpoint(dcontext_t *dcontext, instrlist_t *ilist, app_pc tag,
                           instr_t *ibl_instr, bool is_return, int syscall_number)
{
    audit_callbacks->audit_indirect_branchpoint(dcontext, ilist, tag, ibl_instr,
                                                is_return, syscall_number);
}

inline uint
audit_return(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag)
{
    audit_callbacks->audit_return(dcontext, ilist, next, tag);
}

/* ibl gencode */

inline void
audit_gencode_phase(bool start)
{
    audit_callbacks->audit_gencode_phase(start);
}

inline void
audit_instr(instr_t *instr, byte *copy_pc)
{
    audit_callbacks->audit_instr(instr, copy_pc);
}

inline void
audit_instrument_ibl_indirect_handler(dcontext_t *dcontext, instrlist_t *ilist,
                                      app_pc ibl_routine_start_pc,
                                      instr_t *fragment_not_found_handler)
{
    audit_callbacks->audit_instrument_ibl_indirect_handler(dcontext, ilist,
                                                           ibl_routine_start_pc,
                                                           fragment_not_found_handler);
}

inline void
audit_instrument_ibl_indirect_hook(dcontext_t *dcontext, instrlist_t *ilist,
                                   app_pc ibl_routine_start_pc)
{
    audit_callbacks->audit_instrument_ibl_indirect_hook(dcontext, ilist,
                                                        ibl_routine_start_pc);
}

inline void
audit_instrument_ibl_fcache_return(dcontext_t *dcontext, instrlist_t *ilist,
                                   app_pc ibl_routine_start_pc)
{
    audit_callbacks->audit_instrument_ibl_fcache_return(dcontext, ilist,
                                                        ibl_routine_start_pc);
}

inline void
audit_code_modification(dcontext_t *dcontext, fragment_t *f, app_pc next_pc,
                        app_pc target, size_t write_size)
{
    audit_callbacks->audit_code_modification(dcontext, f, next_pc, target, write_size);
}

inline void
audit_gencode_ibl_routine(app_pc pc, bool syscall)
{
    audit_callbacks->audit_gencode_ibl_routine(pc, syscall);
}

/* miscellaneous */

inline void
audit_heartbeat(dcontext_t *dcontext)
{
    audit_callbacks->audit_heartbeat(dcontext);
}

inline void
audit_intercept(app_pc start, app_pc end)
{
    audit_callbacks->audit_intercept(start, end);
}

#ifdef WINDOWS

/* callbacks */

inline void
audit_callback_context_switch(dcontext_t *dcontext, bool is_return)
{
    audit_callbacks->audit_callback_context_switch(dcontext, is_return);
}

inline void
audit_nested_shadow_stack(dcontext_t *dcontext, bool push)
{
    audit_callbacks->audit_nested_shadow_stack(dcontext, push);
}

inline void
audit_nt_continue()
{
    audit_callbacks->audit_nt_continue();
}

/* network */

inline void
audit_socket_handle(dcontext_t dcontext, HANDLE handle, bool created)
{
    audit_callbacks->audit_socket_handle(dcontext, handle, created);
}

inline void
audit_device_io_control(dcontext_t *dcontext, uint result, HANDLE socket, HANDLE event,
                        IO_STATUS_BLOCK *status_block, IoControlCode control_code,
                        byte *input_data, uint input_length,
                        byte *output_data, uint output_length)
{
    audit_callbacks->audit_device_io_control(dcontext, result, socket, event,
                                             status_block, control_code, input_data,
                                             input_length, output_data, output_length);
}

inline void
audit_wait_for_single_object(dcontext_t *dcontext, HANDLE event)
{
    audit_callbacks->audit_wait_for_single_object(dcontext, event);
}

inline void
audit_wait_for_multiple_objects(dcontext_t *dcontext, uint result, uint handle_count,
                                HANDLE *handles, bool wait_all)
{
    audit_callbacks->audit_wait_for_multiple_objects(dcontext, result, handle_count,
                                                     handles, wait_all);
}
#endif /* WINDOWS */

static void
audit_noop()
{
}

#endif /* SECURITY_AUDIT */

#endif
