#ifndef CROWD_SAFE_TRACE_H
#define CROWD_SAFE_TRACE_H 1

#include "link_observer.h"
#include "module_observer.h"
#include "network_monitor.h"
#include "crowd_safe_util.h"
//#include "../../core/synch.h"

typedef enum trace_file_id trace_file_id;
enum trace_file_id {
    block_hash_file,
    pair_hash_file,
    module_file,
    graph_node_file,
    graph_edge_file,
    graph_cross_module_file,
    network_monitor_file,
    call_stack_file,
    meta_file,
    disassembly_file,
    cross_module_hash_file,
    _trace_file_id_count
};

/* Files are activated by the options passed to drrun:
     -block_hash:            { block_hash_file }
     -pair_hash:             { pair_hash_file }
     -bb_graph:              { module_file, graph_node_file, graph_edge_file, graph_cross_module_file }
     -netmon:                { module_file, network_monitor_file, call_stack_file }
     -xhash:                 { cross_module_hash_file }
     -bb_analysis_level > 0  { disassembly_file }
*/

typedef struct instruction_trace_t instruction_trace_t;
struct instruction_trace_t {
    app_pc tag;
    uint instruction_count;
    uint syscall_number;
    uint *aligned_instructions; // (4 * uint) per instruction (max size on x86 is 15 bytes)
    bb_hash_t block_hash;
};

void
init_crowd_safe_trace(bool isFork);

void
write_hash(bb_hash_t hash, trace_file_id file);

void
write_link(dcontext_t *dcontext, app_pc from, app_pc to, bb_state_t *from_state, bb_state_t *to_state,
    module_location_t *from_module, module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type);

void
write_network_event(network_event_type_t type, network_event_status_t status, network_address_t *address,
    network_protocol_t protocol, uint payload_length, ushort call_stack_id, ushort socket_id, uint thread_id,
    uint64/*not a clock_type_t*/ timestamp);

ushort
write_call_stack(stack_frame_t *frames, uint frame_count);

void
write_meta_header();

void
write_meta_timepoint();

void
write_meta_uib(app_pc from, app_pc to, uint edge_index, bool is_cross_module,
    bool is_admitted, uint traversal_count);

void
write_meta_uib_interval(byte span, byte type_id, uint count, ushort max_consecutive);

void
write_meta_suspicious_syscall(dcontext_t *dcontext, int sysnum, stack_suspicion_t *suspicion);

void
write_meta_suspicious_gencode_entry(ushort uib_count, ushort suib_count);

uint
get_file_entry_count(trace_file_id file_id);

void
finalize_metadata();

void
write_cross_module_hash(uint relative_address, function_export_t export);

void
notify_code_modification(dcontext_t *dcontext, dr_fragment_t *exception_f, app_pc resume_tag, app_pc target, uint size);

void
notify_dynamorio_interception(app_pc intercepted_function_pc, app_pc continuation_pc);

void
add_pending_edge(app_pc from, app_pc to, byte exit_ordinal, graph_edge_type type,
    module_location_t *from_module, module_location_t *to_module, bool holds_lock_already);

void
commit_incoming_edges(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc tag,
    bb_state_t *state, graph_meta_type meta_type, module_location_t *module);

void
notify_incoming_link(dcontext_t *dcontext, app_pc from, app_pc to);

void
notify_basic_block_linking_complete(dcontext_t *dcontext, app_pc tag);

void
notify_process_fork(dcontext_t *dcontext, const wchar_t *child_process_name);

void
confine_to_black_box(module_location_t *anonymous_module, /*module_location_t *owner_module,*/
                     bb_hash_t entry_hash, bb_hash_t exit_hash, char *basis, app_pc from);

void
print_module_entry(const char *action, const char *module_id, app_pc start, app_pc end);

void
write_instruction_trace(instruction_trace_t *trace);

/* Check the level of BB analysis content requested by the user, if any. */
bool
is_bb_analysis_level_active(uint level);

void
crowd_safe_heartbeat(dcontext_t *dcontext);

void
close_crowd_safe_trace();

inline void
output_lock_acquire() {
    extern void *output_mutex;
    dr_mutex_lock(output_mutex);
}

inline void
output_lock_release() {
    extern void *output_mutex;
    dr_mutex_unlock(output_mutex);
}

inline void
assert_output_lock() {
    extern void *output_mutex;
    ASSERT(dr_mutex_self_owns(output_mutex));
}

inline void
assert_output_unlock() {
    extern void *output_mutex;
    ASSERT(!dr_mutex_self_owns(output_mutex));
}
#endif
