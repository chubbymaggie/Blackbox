#include "crowd_safe_trace.h"
#include "link_observer.h"
#include "indirect_link_observer.h"
#include "crowd_safe_util.h"
#include "basic_block_hashtable.h"
#include "indirect_link_hashtable.h"
#include "execution_monitor.h"
#include "blacklist.h"
#include "drvector.h"
#include "drhashtable.h"
//#include "../../core/globals.h"
//#include "../../core/fragment.h"
//#include "../../core/monitor.h"
//#include "../../core/x86/instrument.h"
//#include "../../core/x86/disassemble.h"
//#include "../../core/win32/os_private.h"
#include "ntdll.h"
#include <intrin.h>

#define DOS_HEADER(base)  ((IMAGE_DOS_HEADER *)(base))
#define NT_HEADER(base)   ((IMAGE_NT_HEADERS *)((ptr_uint_t)(base) + DOS_HEADER(base)->e_lfanew))

#define IS_SAME_MODULE(a, b) ((a->monitor_data != NULL) && (b->monitor_data != NULL)) && \
    (((drvector_t *)a->monitor_data)->array == ((drvector_t *)b->monitor_data)->array)

/**** private fields ****/

typedef struct trace_file_t trace_file_t;
struct trace_file_t {
    bool active;
    bool buffered;
    uint buffer_position; // step of 1 per sizeof(uint64)
    uint buffer_size;
    uint entry_count;
    clock_type_t last_buffer_flush;
    file_t file;
    uint64* buffer;
};

static trace_file_t *trace_files;

static hashtable_t *call_continuations;

static module_location_t *internal_fake_module = (module_location_t*)int2p(1);

void *output_mutex;

static bool *output_files_closed = NULL;

#define PERMANENT_MODULE_INSTANCE_HASH ((ushort)0xffff)

#define GRAPH_BUFFER_LONG_COUNT 512
#define CALL_CONTINUATION_KEY_SIZE 10

// #define WATCH_TAG_ACTIVE 1
#ifdef WATCH_TAG_ACTIVE
static app_pc watch_tag = (app_pc)0x7623a72dU; // to 0x770225f2 (ntdll!NtdllDispatchMessage_W)
#endif

typedef struct incoming_edge_t incoming_edge_t;
struct incoming_edge_t {
    app_pc from;
    byte exit_ordinal;
    graph_edge_type type;
    ushort module_instance_hash; // from_module->image_instance_id + to_module->image_instance_id
};

#define MULTIMAP_NAME_KEY incoming_edge_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE incoming_edge_t*
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_NAME_KEY incoming_edge_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE incoming_edge_t*
#include "../drcontainers/drmultimapx.h"

static incoming_edge_multimap_t *pending_incoming_edges;

typedef enum meta_entry_type meta_entry_type;
enum meta_entry_type {
    meta_entry_type_timepoint,
    meta_entry_type_uib,
    meta_entry_type_uib_interval,
    meta_entry_type_suspicious_syscall,
    meta_entry_type_suspicious_gencode
};

/**** private prototypes ****/

static void
write_basic_block(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, module_location_t *module, app_pc tag, bb_state_t *state);

static void
write_committed_basic_block(app_pc tag, bb_state_t *state);

static app_pc
write_graph_edge(dcontext_t *dcontext, app_pc from, app_pc to, bb_state_t *from_state, bb_state_t *to_state,
    module_location_t *from_module, module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type);

static app_pc
write_cross_module_edge(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc from,
    app_pc to, bb_state_t *from_state, bb_state_t *to_state, module_location_t *from_module,
    module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type, bb_hash_t edge_hash);

static void
install_ibp(dcontext_t *dcontext, app_pc from, app_pc to, module_location_t *from_module,
    module_location_t *to_module, bb_state_t *from_state, bb_state_t *to_state, bool verified, bool is_return);

static void
activate_trace_file(trace_file_id id, bool active, bool buffered,
                    uint buffer_size, const char *basename, const char *extension);

static inline void
write_byte_aligned_file_entry(trace_file_id id, uint64 data);

static inline void
flush_trace_buffer(trace_file_t *trace_file);

static void
close_active_trace_files();

static void
close_active_trace_file(trace_file_t *trace_file);

static bool
find_in_exports(IMAGE_EXPORT_DIRECTORY *exports, size_t exports_size, app_pc from, app_pc to,
    module_location_t *from_module, module_location_t *to_module, char *function_id);

/* deprecated
static bool
find_in_imports(app_pc from, app_pc to, module_location_t *from_module,
    module_location_t *to_module, char *function_id);
*/

static char*
get_cross_module_name(module_location_t *module);

static byte
get_black_box_callout_ordinal(graph_edge_type edge_type);

static incoming_edge_t*
create_pending_edge(app_pc from, byte exit_ordinal, graph_edge_type type, ushort module_instance_hash);

static void
free_incoming_edge(void *cc);

/**** public functions ****/

void
init_crowd_safe_trace(bool isFork) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    output_mutex = dr_mutex_create();
    CS_TRACK(output_mutex, sizeof(mutex_t));

    if (isFork) {
        close_active_trace_files();
    } else {
        trace_files = (trace_file_t*)CS_ALLOC(_trace_file_id_count * sizeof(trace_file_t));

        if (CROWD_SAFE_BB_GRAPH()) {
            pending_incoming_edges = (incoming_edge_multimap_t *)CS_ALLOC(sizeof(incoming_edge_multimap_t));
            incoming_edge_multimap_init(pending_incoming_edges, free_incoming_edge, "pending incoming edges");
        }
    }

    output_files_closed = CS_ALLOC(sizeof(bool));
    *output_files_closed = false;

    activate_trace_file(module_file, CROWD_SAFE_MODULE_LOG(), false, 0U, "module", "log");
    activate_trace_file(block_hash_file, CROWD_SAFE_BLOCK_HASH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "block-hash", "dat");
    activate_trace_file(pair_hash_file, CROWD_SAFE_PAIR_HASH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "pair-hash", "dat");
    activate_trace_file(graph_node_file, CROWD_SAFE_BB_GRAPH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "graph-node", "dat");
    activate_trace_file(graph_edge_file, CROWD_SAFE_BB_GRAPH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "graph-edge", "dat");
    activate_trace_file(graph_cross_module_file, CROWD_SAFE_BB_GRAPH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "cross-module", "dat");
    activate_trace_file(network_monitor_file, CROWD_SAFE_NETWORK_MONITOR(), true,
                        GRAPH_BUFFER_LONG_COUNT, "network-monitor", "dat");
    activate_trace_file(call_stack_file, CROWD_SAFE_NETWORK_MONITOR(), true,
                        GRAPH_BUFFER_LONG_COUNT, "call-stack", "dat");
    activate_trace_file(meta_file, CROWD_SAFE_BB_GRAPH(), true,
                        GRAPH_BUFFER_LONG_COUNT, "meta", "dat");
    /* activate cross_module_hash_file on demand */
    activate_trace_file(disassembly_file, is_bb_analysis_level_active(BB_ANALYSIS_ASSEMBLY),
                        false, 0, "disassembly", "log");

    if (CROWD_SAFE_BB_GRAPH()) {
        module_handle_t ntdllh = get_ntdll_base();
        byte *RtlUserThreadStart = (byte *)get_proc_address(ntdllh, "RtlUserThreadStart");
        add_pending_edge(PROCESS_ENTRY_POINT, RtlUserThreadStart, 0, direct_edge, internal_fake_module, internal_fake_module, false);
    }
}

void
write_hash(bb_hash_t hash, trace_file_id file_id) {
    assert_output_lock();
    write_byte_aligned_file_entry(file_id, hash);
    trace_files[file_id].entry_count++;
}

void
write_link(dcontext_t *dcontext, app_pc from, app_pc to, bb_state_t *from_state, bb_state_t *to_state,
    module_location_t *from_module, module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type)
{
    bb_hash_t from_hash, hash;
#ifdef SEED_TLS_FOR_IBL_VERIFICATION
    bb_hash_t temp_from_hash;
#endif

    assert_hashcode_lock();
    ASSERT(from_state != NULL);
    ASSERT(to_state != NULL);

    write_graph_edge(dcontext, from, to, from_state, to_state, from_module, to_module, exit_ordinal, edge_type);

    if (CROWD_SAFE_PAIR_HASH()) { // cs-todo: translate a split 'from' to its exception block?
#ifdef SEED_TLS_FOR_IBL_VERIFICATION
        temp_from_hash = (bb_hash_t)0x100;
        from_hash = temp_from_hash;
#else
        from_hash = from_state->hash;
#endif

        // CS-TODO: only hash the `from` instructions up to the exit ordinal

        hash = (from_hash << 1) ^ to_state->hash;
        if (CROWD_SAFE_PAIR_HASH()) {
            output_lock_acquire();
            write_hash(hash, pair_hash_file);
            trace_files[pair_hash_file].entry_count++;
            output_lock_release();
        }

        /* cs-todo
        if (is_bb_analysis_level_active(BB_ANALYSIS_ASSEMBLY) && CROWD_SAFE_PAIR_HASH()) {
            dr_fprintf(trace_files[disassembly_file].file,
                ">>>> Pair Hash 0x%llx ---- from "PX" to "PX" <<<<\n", hash, from, to);
        }
        */
    }
}

void
write_network_event(network_event_type_t type, network_event_status_t status, network_address_t *address,
    network_protocol_t protocol, uint payload_length, ushort call_stack_id, ushort socket_id, uint thread_id,
    uint64 timestamp)
{
    uint64 entry;

    output_lock_acquire();

    if (!CROWD_SAFE_META_ON_CLOCK())
        write_meta_timepoint();

    write_byte_aligned_file_entry(network_monitor_file, timestamp);

    entry = call_stack_id;
    entry |= (((uint64) socket_id) << 0x10);
    entry |= (((uint64) thread_id) << 0x20);
    write_byte_aligned_file_entry(network_monitor_file, entry);

    write_byte_aligned_file_entry(network_monitor_file, payload_length);

    entry = type;
    entry |= (((uint64) status) << 4);
    entry |= (((uint64) protocol) << 8);
    entry |= (((uint64) address->port) << 0x10);
    entry |= (((uint64) address->ip) << 0x20);
    write_byte_aligned_file_entry(network_monitor_file, entry);

    trace_files[network_monitor_file].entry_count++;
    output_lock_release();
}

ushort
write_call_stack(app_pc *tags, uint tag_count) {
    uint i;
    uint64 entry;

    output_lock_acquire();

    for (i = 0; i < (tag_count - 1); i += 2) {
        entry = p2int(tags[i | 1]);
        entry |= (((uint64) tags[i]) << 0x20);
        write_byte_aligned_file_entry(call_stack_file, entry);
    }

    if ((tag_count & 1) == 0)
        entry = (((uint64) tags[tag_count - 1]) << 0x20);
    else
        entry = 0ULL;
    write_byte_aligned_file_entry(call_stack_file, entry);

    i = trace_files[call_stack_file].entry_count++;
    output_lock_release();
    return (ushort) i;
}

void
write_meta_header() {
    module_data_t *main = dr_get_main_module();
    uint64 header = (uint64)main->start;

    output_lock_acquire();
    write_byte_aligned_file_entry(meta_file, header);
    flush_trace_buffer(&trace_files[meta_file]);
    output_lock_release();
}

void
write_meta_timepoint() {
    uint64 entry = meta_entry_type_timepoint;
    entry |= ((((uint64) trace_files[network_monitor_file].entry_count) & 0xfffff) << 8);
    entry |= ((((uint64) trace_files[graph_cross_module_file].entry_count) & 0xfff) << 0x1c);
    entry |= ((((uint64) trace_files[graph_edge_file].entry_count) & 0xfff) << 0x28);
    entry |= ((((uint64) trace_files[graph_node_file].entry_count) & 0xfff) << 0x34);

    write_byte_aligned_file_entry(meta_file, entry);

    assert_output_lock();
}

void
write_meta_uib(app_pc from, app_pc to, uint edge_index, bool is_cross_module,
    bool is_admitted, uint traversal_count)
{
    uint64 entry = meta_entry_type_uib;
    entry |= (uint64)(edge_index << 8);
    entry |= (((uint64) (traversal_count & 0x3fffffffUL)) << 0x20);
    if (is_cross_module)
        entry |= 0x8000000000000000ULL;
    if (is_admitted)
        entry |= 0x4000000000000000ULL;

    write_byte_aligned_file_entry(meta_file, entry);

    CS_DET("Writing UIB for edge #%d: %d traversals\n", edge_index, traversal_count);

    assert_output_lock();
}

void
write_meta_uib_interval(byte span, byte type_id, uint count, ushort max_consecutive) {
    uint64 entry = meta_entry_type_uib_interval;
    entry |= (((uint64) type_id) << 8);
    entry |= (((uint64) span) << 0xa);
    entry |= (((uint64) max_consecutive) << 0x10);
    entry |= (((uint64) count) << 0x20);

    write_byte_aligned_file_entry(meta_file, entry);

    CS_DET("Writing UIB interval for %s@10^%d: %d (%d consecutive)\n",
        (type_id == 0) ? "all" : (type_id == 1) ? "uib" : "suib",
        span, count, max_consecutive);

    assert_output_lock();
}

void
write_meta_suspicious_syscall(dcontext_t *dcontext, int sysnum, stack_suspicion_t *suspicion) {
    uint64 entry = meta_entry_type_suspicious_syscall;

    /* old format
    entry |= (((uint64) suspicion->suib_count) << 8);
    entry |= (((uint64) suspicion->uib_count) << 0x18);
    entry |= (((uint64) sysnum) << 0x28);
    entry |= (((uint64) compound_raising_edge) << 0x38);
    */

    /* new format */
    if (suspicion->raising_edge_is_cross_module)
        entry |= 0x100ULL;
    entry |= (((uint64) (suspicion->raising_edge_index & 0xffffff)) << 0x10);
    entry |= (((uint64) sysnum) << 0x28);

    output_lock_acquire();
    write_byte_aligned_file_entry(meta_file, entry);
    NOTIFY_SYSCALL_PREDICATE(dcontext, sysnum);
    output_lock_release();
}

void
write_meta_suspicious_gencode_entry(ushort uib_count, ushort suib_count) {
    uint64 entry = meta_entry_type_suspicious_gencode;
    entry |= (((uint64) suib_count) << 8);
    entry |= (((uint64) uib_count) << 0x18);
    entry |= ((((uint64) trace_files[graph_cross_module_file].entry_count) & 0xffffff) << 0x28);

    write_byte_aligned_file_entry(meta_file, entry);

    assert_output_lock();
}

void
finalize_metadata() {
    if (CROWD_SAFE_BB_GRAPH()) {
        output_lock_acquire();
        flush_trace_buffer(&trace_files[meta_file]);
        output_lock_release();
    }
}

void
write_cross_module_hash(uint relative_address, function_export_t export) {
    ASSERT(CROWD_SAFE_RECORD_XHASH());

    output_lock_acquire();
    if (!trace_files[cross_module_hash_file].active) {
        activate_trace_file(cross_module_hash_file, CROWD_SAFE_RECORD_XHASH(), false,
                            0, "xhash", "tab");
    }

    dr_fprintf(trace_files[cross_module_hash_file].file,
               "0x%llx %s "PX"\n", export.hash, export.function_id, (app_pc) relative_address);
    output_lock_release();
}

uint
get_file_entry_count(trace_file_id file_id) {
    return trace_files[file_id].entry_count;
}

void
notify_code_modification(dcontext_t *dcontext, fragment_t *exception_f, app_pc resume_tag, app_pc target, size_t size) {
    if (CROWD_SAFE_BB_GRAPH()) {
        crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
        module_location_t *module = get_module_for_address(exception_f->tag);

        observe_shadow_page_write(dcontext, module, exception_f->tag, target, size);

        CS_LOG("W+X| Exception continuation at %s("PX") for write of "PX" + 0x%x\n",
            module->module_name, MODULAR_PC(module, exception_f->tag), target, size);

        SET_EXCEPTION_RESUMING(cstl);

        hashcode_lock_acquire(); {
            bb_state_t *resume_state = get_bb_state(resume_tag);
            if ((resume_state == NULL) || !IS_BB_EXCEPTION(resume_state)) {
                bb_state_t *exception_block_state = get_bb_state(exception_f->tag);
                byte exit_ordinal = count_ordinals(exception_f);
                if ((resume_state != NULL) && IS_BB_LIVE(resume_state)) {
                    write_graph_edge(dcontext, exception_f->tag, resume_tag, exception_block_state, resume_state,
                        module, module, exit_ordinal, exception_continuation_edge);

                    SET_BB_EXCEPTION(resume_state);

                    CS_DET("Exception continuation edge %s("PX") - "PX" directly written for target "PX"\n",
                        module->module_name, MODULAR_PC(module, exception_f->tag), resume_tag, target);
                } else {
                    incoming_edge_multimap_add(pending_incoming_edges, resume_tag,
                        create_pending_edge(exception_f->tag, exit_ordinal, exception_continuation_edge,
                            2 * module->image_instance_id));

                    CS_DET("Exception continuation edge %s("PX") - "PX" pending for target "PX"\n",
                        module->module_name, MODULAR_PC(module, exception_f->tag), resume_tag, target);
                }

                SET_BB_EXCEPTION(exception_block_state);
            }
        }
        hashcode_lock_release();
    }
}


void
notify_dynamorio_interception(app_pc intercepted_function_pc, app_pc continuation_pc) {
    if (!CROWD_SAFE_BB_GRAPH())
        return;

    hashcode_lock_acquire(); {
        bb_state_t state = { 0, BB_STATE_DYNAMO_INTERCEPT, 0ULL, graph_non_meta, 0 }; // not live now
        insert_bb_state(intercepted_function_pc, state);
    }

    add_pending_edge(intercepted_function_pc, continuation_pc, 1, call_continuation_edge,
        internal_fake_module, internal_fake_module, true);

    hashcode_lock_release();

    CS_LOG("Writing intercept continuation "PX" - "PX"\n", intercepted_function_pc, continuation_pc);
}

void
add_pending_edge(app_pc from, app_pc to, byte exit_ordinal, graph_edge_type type,
    module_location_t *from_module, module_location_t *to_module, bool holds_lock_already)
{
    ushort module_instance_hash;

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    if ((from_module == internal_fake_module) ||
        ((from_module != NULL) && (from_module->type == module_type_anonymous))) // if incorrect, safe to discard during transform
    {
        module_instance_hash = PERMANENT_MODULE_INSTANCE_HASH;
    } else {
        if (from_module == NULL)
            from_module = get_module_for_address(from);
        if (to_module == NULL)
            to_module = get_module_for_address(to);
        module_instance_hash = (from_module->image_instance_id + to_module->image_instance_id);

        if (from_module == &unknown_module)
            CS_ERR("Adding a pending edge from an unknown module at "PX"\n", from);
        if (to_module == &unknown_module)
            CS_WARN("Adding a pending edge to an unknown module at "PX"\n", to);
    }

    if (!holds_lock_already)
        hashcode_lock_acquire();

    {
        incoming_edge_t *edge;
        bool duplicate = false;

        // todo: hottest spot in Chrome (~15%) during page load
        // this will also be an issue with the full JIT optimization
        // maybe replace with a 4-way hash key, similar to blacklist?
        incoming_edge_multimap_entry_t *pending_edges = incoming_edge_multimap_lookup(pending_incoming_edges, to);
        uint i, pending_edge_count = incoming_edge_multimap_item_count(pending_edges);
        for (i = 0; i < pending_edge_count; i++) {
            edge = incoming_edge_multimap_entry_get_item(pending_edges, i);
            if ((edge->from == from) && (edge->module_instance_hash == module_instance_hash)) {
                duplicate = true;
                break;
            }
        }

        if (!duplicate) {
            incoming_edge_multimap_add(pending_incoming_edges, to,
                create_pending_edge(from, exit_ordinal, type, module_instance_hash));
        }

        // CS_LOG("Pend edge type %d "PX"-"PX" at ordinal %d\n", type, from, to, exit_ordinal);
    }

    if (!holds_lock_already)
        hashcode_lock_release();
}

void
commit_incoming_edges(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc tag,
    bb_state_t *state, graph_meta_type meta_type, module_location_t *module)
{
    bool edges_reach_building_tag = false;
    incoming_edge_multimap_entry_t *pending_edges;
    uint pending_edge_count = 9999999;

    assert_hashcode_lock();
    ASSERT(tag == GET_BUILDING_TAG(cstl));

    pending_edges = incoming_edge_multimap_lookup(pending_incoming_edges, tag);
    if (pending_edges != NULL) {
        uint i;
        incoming_edge_t *edge;
        bb_state_t *from_state;
        module_location_t *from_module;
        app_pc committed_edge_target;
        ushort module_instance_hash;

        pending_edge_count = incoming_edge_multimap_item_count(pending_edges);
        for (i = 0; i < pending_edge_count; i++) {
            edge = incoming_edge_multimap_entry_get_item(pending_edges, i);
            from_state = get_bb_state(edge->from);
            from_module = get_module_for_address(edge->from);
            committed_edge_target = NULL;

            module_instance_hash = (from_module->image_instance_id + module->image_instance_id);
            if ((edge->module_instance_hash != module_instance_hash) &&
                (edge->module_instance_hash != PERMANENT_MODULE_INSTANCE_HASH))
            {
                CS_DET("Skipping stale pending edge "PX" - "PX". Hash at pending was %d but now is %d.\n",
                    edge->from, tag, edge->module_instance_hash, module_instance_hash);
                continue;
            }

            if (IS_BLACK_BOX(module) && IS_BLACK_BOX(from_module) &&
                (module->black_box_exit == from_module->black_box_exit) &&
                IS_BB_BLACK_BOX(from_state))
            {
                if (!IS_BB_BLACK_BOX(state)) {
                    assign_to_black_box(state);
                    CS_DET("Make BB ("PX"-v%d 0x%llx) a black box node on the basis of edge (type %d, ordinal %d) from "PX"\n",
                        tag, state->tag_version, state->hash, edge->type, edge->exit_ordinal, edge->from);
                }
            } else {
                if (IS_BB_DYNAMO_INTERCEPT(from_state) && !IS_BB_LIVE(from_state)) {
                    bb_state_t *system_state = get_bb_state(SYSTEM_ENTRY_POINT);

                    CS_LOG("Writing system entry to "PX" because it is not live during edge to "PX"\n", edge->from, tag);
                    //CS_LOG("Activating BB "PFX" for system entry\n", edge->from);

                    from_state->hash = (bb_hash_t)OP_jmp;
                    ACTIVATE_BB(from_state);
                    SET_BB_LINKED(from_state);
                    write_basic_block(dcontext, cstl, from_module, edge->from, from_state);

                    write_graph_edge(dcontext, SYSTEM_ENTRY_POINT, edge->from, system_state, from_state,
                        &system_module, from_module, 0, direct_edge);
                }

                if (IS_GENCODE_EDGE(edge->type)) { // cs-todo: pending gencode edges have from/to reversed--confusing!
                    if (IS_BB_LIVE(from_state)) {
                        CS_DET("DMP| Gencode edge %s("PX") -> "PX" type %d lazy-written\n",
                            module->module_name, MODULAR_PC(module, tag), edge->from, edge->type);
                        committed_edge_target = write_graph_edge(dcontext, tag, edge->from, state, from_state,
                            module, from_module, edge->exit_ordinal, edge->type);
                    } else {
                        CS_DET("DMP| Gencode edge %s("PX") -> "PX" type %d pending but skipped because the gencode target is not live\n",
                            module->module_name, MODULAR_PC(module, tag), edge->from, edge->type);
                    }
                } else {
                    committed_edge_target = write_graph_edge(dcontext, edge->from, tag, from_state, state,
                        from_module, module, edge->exit_ordinal, edge->type);

                    if (edge->type == exception_continuation_edge)
                        CS_DET("Exception continuation edge %s("PX") to "PX" lazy-written\n",
                            from_module->module_name, MODULAR_PC(from_module, edge->from), tag);
                }
            }

            edges_reach_building_tag |= (committed_edge_target == tag);
        }
        incoming_edge_multimap_remove_entry(pending_incoming_edges, tag);
    }

    /* if (edges_reach_building_tag)
        approve_linkage(cstl, "edge");
    else if (IS_BB_BLACK_BOX(state))
        approve_linkage(cstl, "black box containment");
    */
}

void
notify_incoming_link(dcontext_t *dcontext, app_pc from, app_pc to) {
    if (CROWD_SAFE_BB_GRAPH()) {
        crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
        bb_state_t *from_state, *state = GET_BB_STATE(cstl);
        module_location_t *module, *from_module;
        app_pc committed_edge_target = NULL;
        byte exit_ordinal;
        fragment_t *from_f;


        ASSERT(GET_BUILDING_TAG(cstl) == to);

        if (state == NULL) {
            CS_ERR("BB state is null in notify_incoming_link("PFX"->"PFX")!\n", from, to);
            return;
        }

        if (IS_BB_COMMITTED(state) || IS_BB_BLACK_BOX(state)) {
            CS_DET("Skipping edge "PX" - "PX" for %s block\n", from, to, (IS_BB_BLACK_BOX(state) ? "black box" : "committed"));
            return; // cs-todo: do we miss any edges this way?
        }

        hashcode_lock_acquire();

        from_state = get_bb_state(from);
        from_module = get_module_for_address(from);
        module = get_module_for_address(to);
        if (IS_BLACK_BOX(module) && IS_BLACK_BOX(from_module) &&
            (module->black_box_exit == from_module->black_box_exit) &&
            IS_BB_BLACK_BOX(from_state))
        {
            assign_to_black_box(state);
            CS_DET("Make BB ("PX"-v%d 0x%llx) a black box node on the basis of late edge from "PX"\n",
                to, state->tag_version, state->hash, from);
        } else {
            from_f = fragment_lookup(dcontext, from);
            if (from_f == NULL) {
                CS_ERR("Failed to link incoming edge "PX" - "PX" because the 'from' fragment is null, preventing ordinal lookup.\n",
                    from, to);
                return;
            }
            exit_ordinal = find_direct_link_exit_ordinal(from_f, to);

            CS_DET("Writing late edge "PX" - "PX" while building bb "PX"\n", from, to, GET_BUILDING_TAG(cstl));

            committed_edge_target = write_graph_edge(dcontext, from, to, get_bb_state(from), GET_BB_STATE(cstl),
                get_module_for_address(from), get_module_for_address(to), exit_ordinal, direct_edge);
        }

        hashcode_lock_release();

        /*
        if (committed_edge_target == to) {
            approve_linkage(cstl, "late edge");
            CS_DET("Linkage approved by late edge.\n");
        } else if (IS_LINKAGE_APPROVED(cstl)) {
            CS_DET("Linkage has been approved by late edges.\n");
        } else {
            CS_DET("Linkage not approved by late edge: redirected to "PX"\n", committed_edge_target);
        }
        */
    }
}

void
notify_basic_block_linking_complete(dcontext_t *dcontext, fragment_t *f) {
    if (CROWD_SAFE_BB_GRAPH()) {
        crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
        bb_state_t *state = GET_BB_STATE(cstl);
        module_location_t *module = get_module_for_address(f->tag);
        extern bool is_chrome_child;

        if (false) {
            if (TEST(FRAG_IS_TRACE, f->flags))
                CS_LOG("Emitted trace "PX" @"PX"\n", f->tag, f->start_pc);
            else
                CS_LOG("Emitted BB "PX" @"PX"\n", f->tag, f->start_pc);
        }

        if (f->tag != GET_BUILDING_TAG(cstl))
            return;

        if (!(IS_BB_LINKED(state) || IS_BB_DYNAMO(state) ||
              TEST(FRAG_IS_TRACE, f->flags) || module->black_box_singleton != NULL)) {
            if (HAS_CLOBBERED_BLACK_BOX_HASH(cstl) || (GET_LAST_DECODED_TAG(cstl) == f->tag)) {
                reconcile_decode_anomaly(cstl, state);
            } else if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit) &&
                    is_building_trace(dcontext)) {
                    monitor_data_t *md = (monitor_data_t *) dcontext->monitor_field;
                    app_pc from_tag = md->blk_info[md->num_blks-1].info.tag;

                    CS_LOG("Patching trace "PX" tail "PX" into private bb "PX"\n",
                           md->trace_tag, from_tag, f->tag);

                    hashcode_lock_acquire();
                    write_graph_edge(dcontext, from_tag, f->tag, get_bb_state(from_tag), state,
                                     get_module_for_address(from_tag), module, 0/*branch taken*/,
                                     TEST(LINK_RETURN, md->final_exit_flags) ? unexpected_return_edge : indirect_edge);
                    hashcode_lock_release();
            } else {
                linkstub_t *l;

                LOG(THREAD, LOG_LINKS, 1, "No links for new bb "PX"!%s\n", f->tag,
                    is_building_trace(dcontext) ? " (building trace)" : "");
                LOG(GLOBAL, LOG_TOP, 1, "No links for new bb "PX"!\n", f->tag);
                CS_LOG("No links for new bb ("PX"-v%d 0x%llx) on thread 0x%x! %s"
                       "Clobbered black box hash 0x%llx\n", f->tag, state->tag_version,
                       state->hash, current_thread_id(),
                       is_building_trace(dcontext) ? "(building trace) " : "",
                       GET_CLOBBERED_BLACK_BOX_HASH(cstl));

                if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit)) {
                    fragment_t *last_f = dcontext->last_fragment;
                    fragment_t *in_f = linkstub_fragment(dcontext, dcontext->last_exit);

                    CS_LOG("\tIndirect exit for %s %s: "PX".\n",
                           last_f == NULL ? 0 : TEST(FRAG_IS_TRACE, last_f->flags) ? "trace" : "bb",
                           TEST(LINK_RETURN, dcontext->last_exit->flags) ? "ret" :
                           EXIT_IS_CALL(dcontext->last_exit->flags) ? "call*" : "jmp*",
                           in_f == NULL ? (last_f == NULL ? 0 : last_f->tag) : in_f->tag);
                }

                for (l = f->in_xlate.incoming_stubs; l != NULL; l = LINKSTUB_NEXT_INCOMING(l)) {
                    fragment_t *in_f = linkstub_fragment(dcontext, l);
                    CS_LOG("\tFound a linkstub from "PX" with flags 0x%x\n", in_f->tag, l->flags);
                }
            }
        } else {
            CS_DET("Linkage approved for BB "PX"-v%d\n", f->tag, state->tag_version);
        }

        set_building_complete(cstl);
    }
}

void
notify_process_fork(dcontext_t *dcontext, wchar_t *child_process_name) {
    if (CROWD_SAFE_BB_GRAPH()) {
        crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
        bb_hash_t hash = wstring_hash(child_process_name);
        app_pc from_tag = dr_get_main_module()->entry_point;
        module_location_t *from_module = get_module_for_address(from_tag);

        hashcode_lock_acquire();
        write_cross_module_edge(dcontext, cstl, from_tag, CHILD_PROCESS_SINGLETON_PC, get_bb_state(from_tag),
                                get_bb_state(CHILD_PROCESS_SINGLETON_PC), from_module, &system_module,
                                default_edge_ordinal(fork_edge), fork_edge, hash);
        hashcode_lock_release();
    }
    CS_LOG("Fork child process '%S'\n", child_process_name);
}

void
confine_to_black_box(module_location_t *anonymous_module, // module_location_t *owner_module,
                     bb_hash_t entry_hash, bb_hash_t exit_hash, char *basis, app_pc from)
{
    if (assign_black_box_singleton(anonymous_module, entry_hash)) {
        bb_state_t singleton_state = { 0, BB_STATE_LIVE | BB_STATE_COMMITTED | BB_STATE_SINGLETON | BB_STATE_BLACK_BOX,
            entry_hash, graph_meta_singleton, 0 };
        anonymous_module->black_box_singleton_state = insert_bb_state(anonymous_module->black_box_singleton, singleton_state);

        write_committed_basic_block(anonymous_module->black_box_singleton, anonymous_module->black_box_singleton_state);

        // ASSERT(owner_module != NULL);
        // owner_module->black_box_entry = entry_hash;
    } else {
        anonymous_module->black_box_singleton_state = get_bb_state(anonymous_module->black_box_singleton);
    }

    DODEBUG( log_bb_state(anonymous_module->black_box_singleton_state, "Black box singleton state"); );

    CS_LOG("Confining module (%s ["PX"-"PX"]) to black box 0x%llx/0x%llx at fake pc "PX" on the basis of %s at "PX"\n",
           anonymous_module->module_name, anonymous_module->start_pc, anonymous_module->end_pc,
           entry_hash, exit_hash, anonymous_module->black_box_singleton, basis, from);

    anonymous_module->black_box_entry = entry_hash;
    anonymous_module->black_box_exit = exit_hash;
}

void
print_module_entry(const char *action, const char *module_id, app_pc start, app_pc end)
{
    file_t outfile;

    output_lock_acquire();
    outfile = trace_files[module_file].file;

    dr_fprintf(outfile, "(%ld,%ld,%ld,%ld) %s module %s: "PX" - "PX"\n",
        trace_files[graph_node_file].entry_count, trace_files[graph_edge_file].entry_count,
        trace_files[graph_cross_module_file].entry_count, trace_files[network_monitor_file].entry_count,
        action, module_id, start, end);
    output_lock_release();
}

void
write_instruction_trace(instruction_trace_t *trace) {
    if (!is_bb_analysis_level_active(1)) {
        return;
    } else {
        uint64 *aligned_instructions = (uint64*)trace->aligned_instructions;
        uint64 *end = aligned_instructions + (2 * trace->instruction_count);

        output_lock_acquire();
        write_byte_aligned_file_entry(disassembly_file,
            (uint64)trace->tag |
            (((uint64)trace->syscall_number) << 0x20) |
            (((uint64)trace->instruction_count) << 0x30));
        write_byte_aligned_file_entry(disassembly_file, trace->block_hash);
        for (; aligned_instructions < end; aligned_instructions++)
            write_byte_aligned_file_entry(disassembly_file, *aligned_instructions);
        output_lock_release();
    }
}

bool
is_bb_analysis_level_active(uint level) {
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, false);

    return level <= DYNAMO_OPTION(bb_analysis_level);
}

void
crowd_safe_heartbeat(dcontext_t *dcontext) {
    if (CROWD_SAFE_MODULE_LOG()) {
        clock_type_t now = quick_system_time_millis();
        bool flush_now = false;
        trace_file_t *file;
        trace_file_id id;

#ifdef MONITOR_UNEXPECTED_IBP
        if (CROWD_SAFE_BB_GRAPH())
            write_stale_uibp_reports(dcontext, now);
#endif

        for (id = 0; id < _trace_file_id_count; id++) {
            file = &trace_files[id]; // note: allowing an unsafe read here
            if (file->active && file->buffered && ((now - file->last_buffer_flush) > BUFFER_FLUSH_INTERVAL)) {
                flush_now = true;
                break;
            }
        }

        if (flush_now) {
            CS_LOG("Flush buffers at 0x%x\n", now);
            output_lock_acquire();
            for (id = 0; id < _trace_file_id_count; id++) {
                file = &trace_files[id];
                if (file->active && file->buffered)
                    flush_trace_buffer(file);
            }
            output_lock_release();
        }
    }
}

void
close_crowd_safe_trace() {
    if (output_files_closed != NULL && !*output_files_closed) {
        close_active_trace_files();
        /*

        if (CROWD_SAFE_BB_GRAPH()) {
            incoming_edge_multimap_delete(pending_incoming_edges);
            dr_global_free(pending_incoming_edges, sizeof(incoming_edge_multimap_t));
        }

        if (CROWD_SAFE_MONITOR()) {
            close_execution_monitor();
            close_anonymous_execution_monitor();
        }

        */
        dr_mutex_destroy(output_mutex);
        *output_files_closed = true;
    }
}

/**** private functions ****/

static void
write_basic_block(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, module_location_t *module, app_pc tag, bb_state_t *state) {
    assert_hashcode_lock();
    assert_output_unlock();

    SET_BB_COMMITTED(state);

    if (IS_BUILDING_TAG(cstl, tag) && HAS_STATIC_SYSCALL(cstl)) {
        app_pc syscall_singleton_pc = (SYSCALL_SINGLETON_START + GET_STATIC_SYSCALL_NUMBER(cstl));

        write_link(dcontext, tag, syscall_singleton_pc, state, get_bb_state(syscall_singleton_pc),
            module, &system_module, GET_STATIC_SYSCALL_ORDINAL(cstl), direct_edge);
    }

    write_committed_basic_block(tag, state);
}

static inline void
write_committed_basic_block(app_pc tag, bb_state_t *state) {
    uint64 compound_tag = p2int(tag);

    ASSERT(IS_BB_COMMITTED(state));

    if (CROWD_SAFE_BB_GRAPH()) {
        output_lock_acquire();
        *(((byte*)&compound_tag)+0x6) = state->meta_type;
        *(((byte*)&compound_tag)+0x7) = state->tag_version;
        write_byte_aligned_file_entry(graph_node_file, compound_tag);
        write_byte_aligned_file_entry(graph_node_file, state->hash);
        trace_files[graph_node_file].entry_count++;
        output_lock_release();
    }
    if (CROWD_SAFE_BLOCK_HASH()) {
        output_lock_acquire();
        write_hash(state->hash, block_hash_file);
        trace_files[block_hash_file].entry_count++;
        output_lock_release();
    }
}

// cs-todo: for trampoline patches, make sure the pair hash gets written also
static app_pc
write_graph_edge(dcontext_t *dcontext, app_pc from, app_pc to, bb_state_t *from_state, bb_state_t *to_state,
    module_location_t *from_module, module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type)
{
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    bool verified, write_edge, skip_edge = false;
    extern bool blacklist_enabled;

    assert_hashcode_lock();

    validate_ordinal(dcontext, from, to, exit_ordinal, edge_type);

    if ((from_state == NULL) || (to_state == NULL)) {
        CS_ERR("Missing state(s) for link from "PX" to "PX"\n", from, to);
        log_bb_state(from_state, "from");
        log_bb_state(to_state, "to");
        log_bb_meta(&cstl->bb_meta);
        ASSERT((from_state != NULL) || (to_state != NULL));
        skip_edge = true;
    } else if (from_module->type == module_type_dynamo ||
               is_part_of_interception(from) || is_part_of_interception(to)) {
        CS_DET("Dynamo edge filtered out: "PX" --%d|%d--> "PX"\n", from, exit_ordinal, edge_type, to);

        SET_BB_DYNAMO(to_state);
        skip_edge = true;
    } else if (IS_BB_DYNAMO(from_state) || (to_module->type == module_type_dynamo)) {
        skip_edge = true;
    } else if (edge_type != call_continuation_edge) {
#ifndef SEED_TLS_FOR_IBL_VERIFICATION
        // ASSERT((from_module != &unknown_module) && (to_module != &unknown_module)); // seems to happen on fork
#endif
        if (IS_BLACK_BOX(from_module)) {
            // cs-todo: this simplification is lame. We need all incoming edges in DGC.
            if (!IS_BB_BLACK_BOX(from_state)) {
                assign_to_black_box(from_state);

                switch (from_module->type) {
                    case module_type_image:
                        CS_WARN("Inferring black box exit containment by page, without an incoming edge: "
                                PX"->%s"PX"\n", from, to_module->module_name, MODULAR_PC(to_module, to));
                        break;
                    case module_type_anonymous:
                        CS_WARN("Inferring black box edge containment by page, without an incoming edge: "
                                PX"->"PX"\n", from, to);
                }
            }

            switch (edge_type) {
                case unexpected_return_edge:
                    CS_WARN("JIT UR\n");
                    break;
                case gencode_perm_edge:
                    CS_LOG("JIT gencode chmod\n");
                    break;
                case gencode_write_edge:
                    CS_LOG("JIT gencode write\n");
                    break;
            }
        }

        if (from_module == to_module) {
            if (IS_BB_BLACK_BOX(from_state) && IS_BB_BLACK_BOX(to_state)) {
                switch (edge_type) {
                    case gencode_perm_edge:
                        CS_LOG("JIT gencode chmod\n");
                        break;
                    case gencode_write_edge:
                        CS_LOG("JIT gencode write\n");
                        break;
                    case unexpected_return_edge:
                        CS_LOG("JIT UR\n");
                    default:
                        skip_edge = true;
                }
            } else if (IS_BLACK_BOX(to_module)) {
                if (!IS_BB_BLACK_BOX(to_state))
                    assign_to_black_box(to_state);
                switch (edge_type) {
                    case gencode_perm_edge:
                    case gencode_write_edge:
                        break;
                    default:
                        skip_edge = true;
                }
            }
        } else {
            return write_cross_module_edge(dcontext, cstl, from, to, from_state, to_state,
                from_module, to_module, exit_ordinal, edge_type, 0);
        }
    }

    if (skip_edge) {
        if ((edge_type == indirect_edge) || (edge_type == unexpected_return_edge))
            install_ibp(dcontext, from, to, NULL, NULL, NULL, NULL, true, edge_type == unexpected_return_edge);
        return NULL;
    }

    if (from_module->type == module_type_anonymous)
        CS_DET("Write IM edge type %d "PX" - "PX" at ordinal %d\n", edge_type, from, to, exit_ordinal);

    verified = verify_intra_module_edge(dcontext, from_module, to_module, from, to, from_state, to_state, exit_ordinal, edge_type);
    write_edge = (!verified || IS_BB_WHITE_BOX(from_module, from_state)); // white box edge always might be needed

    if ((edge_type == indirect_edge) || (edge_type == unexpected_return_edge)) {
        if (!verified)
            CS_DET("Installing IM-UIB in module %s\n", from_module->module_name);
        install_ibp(dcontext, from, to, from_module, to_module, from_state, to_state, verified, edge_type == unexpected_return_edge);
    }

    if (blacklist_enabled)
        check_blacklist_edge(from_module, to_module, from, to, from_state, to_state, 0ULL, edge_type);

    if (!write_edge) {
        SET_BB_LINKED(to_state);
    } else {
        DODEBUG({
            CS_DET("Intra-module edge %s from "PX" to "PX"\n", from_module->module_name,
                MODULAR_PC(from_module, from), MODULAR_PC(to_module, to));
            //log_bb_state(from_state, "from");
            //log_bb_state(to_state, "to");
        });

        DODEBUG({
            if (to_state == NULL)
                CS_ERR("Missing 'to' node "PX" in CM edge from "PX"\n", to, from);
            else if (!IS_BB_LIVE(to_state))
                CS_ERR("Inactive 'to' node "PX" in CM edge from "PX"\n", to, from);
            ASSERT((to_state != NULL) && IS_BB_LIVE(to_state));
            if (from_state == NULL)
                CS_ERR("Missing 'from' block in IM edge "PX" - "PX". Was module %s recently unloaded?\n",
                    from, to, from_module->module_name);
            ASSERT(from_state != NULL);
        });

        if (IS_BLACK_BOX(from_module) || IS_BLACK_BOX(to_module)) {
            CS_LOG("Writing IM edge for black box 0x%x: "PX"[0x%x]%c -%d-> "PX"[0x%x]%c\n",
                   from_module->black_box_singleton, from, from_state->flags,
                   IS_BB_BLACK_BOX(from_state) ? 'T' : 'F',
                   edge_type, to, to_state->flags,
                   IS_BB_BLACK_BOX(to_state) ? 'T' : 'F');
        }

        if (CROWD_SAFE_BB_GRAPH()) {
            bool committed_bb = false;
            uint64 compoundFromTag = p2int(from);
            uint64 compoundToTag = p2int(to);

            if (!IS_BB_COMMITTED(from_state)) {
                CS_DET("Writing 'from' node of edge "PX" - "PX"\n", from, to);

                committed_bb = true;
                write_basic_block(dcontext, cstl, from_module, from, from_state);
            }
            if (!IS_BB_COMMITTED(to_state)) {
                CS_DET("Writing 'to' node of edge "PX" - "PX"\n", from, to);

                committed_bb = true;
                write_basic_block(dcontext, cstl, to_module, to, to_state);
            }
            SET_BB_LINKED(to_state);

            if (IS_GENCODE_EDGE(edge_type))
                CS_DET("DMP| Buffering edge %s("PX") -%d-> %s("PX") to disk.\n", from_module->module_name,
                    MODULAR_PC(from_module, from), exit_ordinal, to_module->module_name, MODULAR_PC(to_module, to));

            output_lock_acquire();
            *(((byte*)&compoundFromTag)+0x5) = exit_ordinal;
            *(((byte*)&compoundFromTag)+0x6) = edge_type;
            *(((byte*)&compoundFromTag)+0x7) = from_state->tag_version;
            *(((byte*)&compoundToTag)+0x7) = to_state->tag_version;
            write_byte_aligned_file_entry(graph_edge_file, compoundFromTag);
            write_byte_aligned_file_entry(graph_edge_file, compoundToTag);
            trace_files[graph_edge_file].entry_count++;

            if (!verified) {
                flush_trace_buffer(&trace_files[graph_edge_file]);
                if (committed_bb)
                    flush_trace_buffer(&trace_files[graph_node_file]);
		        }
            output_lock_release();
        }
    }

    return to;
}

static app_pc
write_cross_module_edge(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc from,
    app_pc to, bb_state_t *from_state, bb_state_t *to_state, module_location_t *from_module,
    module_location_t *to_module, byte exit_ordinal, graph_edge_type edge_type, bb_hash_t edge_hash)
{
    char function_id[256] = {0};
    extern app_pc *dll_entry_callback_block;
    bool omitted_black_box_edge = false;
    bool verified = false, write_edge = false;
    extern bool blacklist_enabled;
    byte from_tag_version = 0xff, to_tag_version = 0xff;
    app_pc original_from = from;
    app_pc original_to = to;

    assert_hashcode_lock();

    if ((from_module->type == module_type_anonymous) || (to_module->type == module_type_anonymous))
        CS_DET("Write CM edge type %d "PX" - "PX" at ordinal %d\n", edge_type, from, to, exit_ordinal);

    if (edge_hash == 0ULL && to_module->type == module_type_anonymous) {
        char entry_symbol[256], *entry_id = (char *) entry_symbol;
        size_t caller_offset = (from - from_module->start_pc);

        if (IS_GENCODE_EDGE(edge_type))
            dr_snprintf(entry_symbol, 256, "%s@%x->gencode", from_module->module_name, caller_offset);
        else
            dr_snprintf(entry_symbol, 256, "%s@%x->dgc", from_module->module_name, caller_offset);
        edge_hash = string_hash(entry_symbol);

        if (CROWD_SAFE_RECORD_XHASH() && register_xhash(entry_id)) {
            function_export_t call_to_dgc = { edge_hash, entry_id };
            write_cross_module_hash(caller_offset, call_to_dgc);
        }
    }

    if (edge_hash == 0ULL) {
        if (from == *dll_entry_callback_block) {
            CS_DET("Cross-module edge from "PX" to a dll init function at "PX"\n", from, to);
            strcat(function_id, "!DllMain"); // valid for all modules
        } else {
            if ((to_module->type == module_type_image) || (to_module == &system_module)) {
                extern export_hashtable_t *export_hashes;
                edge_hash = export_hashtable_lookup_value(export_hashes, to).hash;
            }

            if (edge_hash == 0U) {
                if (from_module->type == module_type_anonymous && to_module->type == module_type_image) {
                    print_callback_function_id(function_id, 256, to_module, to - to_module->start_pc);
                } else {
                    // "<from-module>/<to-module>!callback"
                    dr_snprintf(function_id, 256, "%s/%s!callback", get_cross_module_name(from_module),
                        get_cross_module_name(to_module));
                }
                // cs-todo: should distinguish unexpected returns, since we do have them in Office apps
            }
        }
    }

    if (edge_hash == 0ULL) {
        edge_hash = string_hash(function_id);

        if (to_module->type == module_type_image) {
            function_export_t internal_export = { edge_hash, cs_strcpy(function_id) };
            add_export_hash(to, to - to_module->start_pc, internal_export, CROWD_SAFE_RECORD_XHASH());
        }
    }

    if ((from_module->type == module_type_anonymous) && (to_module->type == module_type_anonymous) &&
            IS_BLACK_BOX(from_module) && !IS_BLACK_BOX(to_module))
        CS_LOG("Anonymous bridge from black box "PX" to white box "PX". Hash of 'from' is 0x%llx\n",
            from, to, from_state->hash);

    if ((from_module->type == module_type_anonymous) && (to_module->type == module_type_anonymous) &&
            !IS_BLACK_BOX(from_module) && IS_BLACK_BOX(to_module))
        CS_ERR("White box "PX" enters black box "PX". Hash of 'from' is 0x%llx\n",
            from, to, from_state->hash);

    // cs-todo: what if the module gets marked as 'monitored' and a black box entry occurs later?
    if (IS_BLACK_BOX(from_module) && !IS_GENCODE_EDGE(edge_type)) {
        if (IS_BB_BLACK_BOX(from_state)) {
            switch (to_module->type) {
                case module_type_image: {
                    if (from_module->black_box_exit != edge_hash)
                        CS_DET("Black box at "PX" escapes from tag "PX" to module %s at "PX" on edge hash 0x%llx\n",
                            from_module->start_pc, from, to_module->module_name, to, edge_hash);

                    CS_DET("Black box callout "PX"->%s("PX")\n", from, to_module->module_name, MODULAR_PC(to_module, to));

                    from = from_module->black_box_singleton; // redirect the edge: from the black box singleton node
                    from_state = from_module->black_box_singleton_state;
                    exit_ordinal = get_black_box_callout_ordinal(edge_type);
                    from_tag_version = 0;
                } break;
                case module_type_anonymous: {
                    if (IS_BLACK_BOX(to_module)) {
                        if (from_module->black_box_exit == to_module->black_box_exit)
                            omitted_black_box_edge = true; // skip the edge, it is subsumed by the black box singleton node
                        else
                            CS_ERR("Black box at "PX" escapes to a black box ("PX"-"PX") "
                                   "with a different owner (exit hash 0x%llx)\n",
                                   from_module->start_pc, to_module->start_pc, to_module->end_pc,
                                   to_module->black_box_exit);
                    } else if (!IS_GENCODE_EDGE(edge_type)) {
                        confine_to_black_box(to_module, /*NULL,*/ from_module->black_box_entry,
                            from_module->black_box_exit, "peer blackbox", from);
                        assign_to_black_box(to_state);
                        omitted_black_box_edge = true; // skip the edge, it is subsumed by the singleton
                    }
                } break;
                case module_type_meta:
                    CS_ERR("Black box at "PX" escapes to meta module ("PX"-"PX") with exit hash 0x%llx\n",
                        from_module->start_pc, to_module->start_pc, to_module->end_pc, to_module->black_box_exit);
                    break;
                default: CS_ERR("Unknown module type %d!\n", to_module->type);
            }
        } else {
            if (to_module->type == module_type_image) {
                CS_ERR("Found white box edge in black box module: "PX"->%s("PX")\n", from,
                       to_module->module_name, MODULAR_PC(to_module, to));
            } else {
                CS_ERR("Found white box edge in black box module: "PX"->"PX"\n", from);
            }
        }
    } else if ((from_module->type == module_type_image) && (to_module->type == module_type_anonymous) &&
               !IS_GENCODE_EDGE(edge_type)) { /* gencode edges have already been redirected to the singleton */
        if (IS_BLACK_BOX(to_module)) {
            if (to_module->black_box_entry == from_module->black_box_entry) {
                assign_to_black_box(to_state);

                if (!observe_shadow_page_entry(from_module, to)) {
                    CS_ERR("DMP: Can't verify %s("PX") -%d-> %s("PX") because the 'from' module "
                           "fails permission in the shadow page table.\n",
                        from_module->module_name, from, edge_type, to_module->module_name, to);
                }

                to = to_module->black_box_singleton; // redirect the edge: to the black box singleton node
                to_state = to_module->black_box_singleton_state;
                to_tag_version = 0;
            } else {
                CS_LOG("Black box at "PX" is shared by entry %s: %s("PX") to %s("PX") with hash 0x%llx\n",
                    to_module->start_pc, function_id, from_module->module_name, MODULAR_PC(from_module, from),
                    to_module->module_name, MODULAR_PC(to_module, to), edge_hash);
            }
        } else {
            uint i;
            anonymous_black_box_t *black_box;
            for (i = 0; i < black_boxes->entries; i++) {
                black_box = black_boxes->array[i];
                if (black_box->entry_hash == from_module->black_box_entry) {
                    bool isBlackBoxMemory = observe_shadow_page_entry(from_module, to);

                    if (!isBlackBoxMemory) { // && (edge_type == unexpected_return_edge)) {
                        CS_LOG("Black box generator %s takes %d edge to external white box at "PX"\n",
                               from_module->module_name, edge_type, to);
                    } else {
                        if (!isBlackBoxMemory) {
                            CS_ERR("DMP: Can't verify %s("PX") -%d-> %s("PX") "
                                "because the 'from' module fails permission in the shadow page table.\n",
                                from_module->module_name, MODULAR_PC(from_module, from),
                                edge_type, to_module->module_name, to);
                        }

                        assign_to_black_box(to_state);

                        confine_to_black_box(to_module, /*from_module,*/ black_box->entry_hash,
                                             black_box->exit_hash, "entry hash", from);
                        to = to_module->black_box_singleton; // redirect the edge: to the black box singleton node
                        to_state = to_module->black_box_singleton_state;
                        to_tag_version = 0;
                    }
                    break;
                }
            }
        }
    }

    if ((to_module->type == module_type_anonymous) && !IS_GENCODE_EDGE(edge_type))
        write_gencode_edges(dcontext, cstl, original_to, to, to_state, to_module);

    if (!omitted_black_box_edge) {
        if (CROWD_SAFE_MONITOR()) {
            if (IS_SAME_MODULE(from_module, to_module)) // two instances of the same module appears reflexive in the monitor dataset
                verified = verify_intra_module_edge(dcontext, from_module, to_module, from, to, from_state, to_state, exit_ordinal, edge_type);
            else
                verified = verify_cross_module_edge(dcontext, from_module, to_module, from, to, from_state, to_state, edge_hash, edge_type);
        }

        write_edge = (!verified || // white box entry must always be written--we don't know yet whether we need it
            IS_BB_WHITE_BOX(from_module, from_state) || IS_BB_WHITE_BOX(to_module, to_state));

        if (CROWD_SAFE_MONITOR() && (to == CHILD_PROCESS_SINGLETON_PC)) // cs-hack
            CS_LOG("Process fork is %sverified for hash 0x%llx\n", verified ? "" : "not ", edge_hash);
    }
    if ((edge_type == indirect_edge) || (edge_type == unexpected_return_edge)) {
        if (!verified)
            CS_DET("Installing CM-UIB: module %s -> %s\n", from_module->module_name, to_module->module_name);
        install_ibp(dcontext, original_from, original_to, from_module, to_module, from_state,
            to_state, verified || omitted_black_box_edge, edge_type == unexpected_return_edge);
    }

    if (omitted_black_box_edge)
        return NULL;

    if (blacklist_enabled)
        check_blacklist_edge(from_module, to_module, from, to, from_state, to_state, edge_hash, edge_type);

    if (!write_edge) {
        SET_BB_LINKED(to_state);
    } else {
        DODEBUG({
            CS_DET("Cross-module edge %s from %s("PX") to %s("PX")\n", function_id, from_module->module_name,
                MODULAR_PC(from_module, from), to_module->module_name, MODULAR_PC(to_module, to));
            //log_bb_state(from_state, "from");
            //log_bb_state(to_state, "to");
        });

        DODEBUG({
            if (to_state == NULL)
                CS_ERR("Missing 'to' node "PX" in CM edge from "PX"\n", to, from);
            else if (!IS_BB_LIVE(to_state))
                CS_ERR("Inactive 'to' node "PX" in CM edge from "PX"\n", to, from);
            ASSERT((to_state != NULL) && IS_BB_LIVE(to_state));
            if (from_state == NULL)
                CS_ERR("Missing 'from' block in CM edge "PX" - "PX". Was module %s recently unloaded?\n",
                    from, to, from_module->module_name);
            ASSERT(from_state != NULL);
        });

        if (IS_BLACK_BOX(from_module) || IS_BLACK_BOX(to_module)) {
            CS_DET("Writing CM edge for black box 0x%x: "PX" ~> "PX"\n",
                   IS_BLACK_BOX(from_module) ? from_module->black_box_singleton : to_module->black_box_singleton,
                   from_module->start_pc, to_module->start_pc);
        }

        if (CROWD_SAFE_BB_GRAPH()) {
            bool committed_bb = false;
            uint64 compoundFromTag = p2int(from);
            uint64 compoundToTag = p2int(to);

            if (!IS_BB_COMMITTED(from_state)) {
                CS_DET("Writing 'from' node of edge "PX" - "PX"\n", from, to);

                if (IS_BB_SINGLETON(from_state)) {
                    CS_ERR("Writing singleton 0x%x in cross-module edge!\n", from);
                    log_bb_state(from_state, "Singleton");
                }

                committed_bb = true;
                write_basic_block(dcontext, cstl, from_module, from, from_state);
            }
            if (!IS_BB_COMMITTED(to_state)) {
                CS_DET("Writing 'to' node of edge "PX" - "PX"\n", from, to);

                if (IS_BB_SINGLETON(to_state)) {
                    CS_ERR("Writing singleton 0x%x in cross-module edge!\n", to);
                    log_bb_state(to_state, "Singleton");
                }

                committed_bb = true;
                write_basic_block(dcontext, cstl, to_module, to, to_state);
            }

            if (!verified) {
                if (edge_type == gencode_perm_edge)
                    NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, gencode_perm);
                else if (edge_type == gencode_write_edge)
                    NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, gencode_write);
                else if (to == CHILD_PROCESS_SINGLETON_PC)
                    NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, fork);
            }

            if (from_tag_version == 0xff)
                from_tag_version = from_state->tag_version;
            if (to_tag_version == 0xff)
                to_tag_version = to_state->tag_version;

            if (IS_GENCODE_EDGE(edge_type)) {
                CS_DET("DMP| Buffering edge %s("PX") -%d-> %s("PX") to disk.\n", from_module->module_name,
                    MODULAR_PC(from_module, from), exit_ordinal, to_module->module_name, MODULAR_PC(to_module, to));
            } else {
                SET_BB_LINKED(to_state);
            }

            output_lock_acquire();

#ifdef MONITOR_UNEXPECTED_IBP
            if ((from_module->type != module_type_anonymous) &&
                (to_module->type == module_type_anonymous) && (cstl->csd->stack_spy_mark != 0)) {
                write_meta_suspicious_gencode_entry(cstl->stack_suspicion.uib_count, cstl->stack_suspicion.suib_count);
            }
#endif

            *(((byte*)&compoundFromTag)+0x5) = exit_ordinal;
            *(((byte*)&compoundFromTag)+0x6) = edge_type;
            *(((byte*)&compoundFromTag)+0x7) = from_tag_version;
            *(((byte*)&compoundToTag)+0x7) = to_tag_version;
            write_byte_aligned_file_entry(graph_cross_module_file, compoundFromTag);
            write_byte_aligned_file_entry(graph_cross_module_file, compoundToTag);
            write_byte_aligned_file_entry(graph_cross_module_file, edge_hash);
            trace_files[graph_cross_module_file].entry_count++;

            if (!verified) {
                flush_trace_buffer(&trace_files[graph_cross_module_file]);
                if (committed_bb)
                    flush_trace_buffer(&trace_files[graph_node_file]);
            }

            output_lock_release();
        }
    }
    return to;
}

static inline bool
is_relocation_target(module_location_t *module, app_pc target) {
    if (module->relocation_targets == NULL)
        return false;

    return relocation_target_table_lookup_value(module->relocation_targets, p2int(target)) != 0U;
}

static void
install_ibp(dcontext_t *dcontext, app_pc from, app_pc to, module_location_t *from_module,
    module_location_t *to_module, bb_state_t *from_state, bb_state_t *to_state, bool verified, bool is_return)
{
#ifdef MONITOR_UNEXPECTED_IBP
# ifdef MONITOR_ALL_IBP
    bool unexpected = true;
# else
    bool unexpected = (CROWD_SAFE_MONITOR() && !verified);
# endif
#endif

#ifdef MONITOR_UNEXPECTED_IBP
    if (unexpected) {
        bool is_admitted = false;
        uint edge_index;
        if (from_module->type != module_type_anonymous) {
            extern export_hashtable_t *export_hashes;
            function_export_t export = export_hashtable_lookup_value(export_hashes, to);
            if ((export.hash == 0ULL) &&
                !find_unexpected_ibt_precedent(to, to_module, from_module == to_module)) {
                if (is_relocation_target(to_module, to)) {
                    CS_DET("Relocation: admitting target "PX" in %s("PX")->%s("PX")\n", to, from_module->module_name,
                           MODULAR_PC(from_module, from), to_module->module_name, MODULAR_PC(to_module, to));
                } else {
                    // cs-todo: never for anonymous targets
                    CS_DET("Relocation: no target "PX" in %s("PX")->%s("PX")\n", to, from_module->module_name,
                           MODULAR_PC(from_module, from), to_module->module_name, MODULAR_PC(to_module, to));
                }
            }
            is_admitted = (export.hash != 0ULL) ||
                find_unexpected_ibt_precedent(to, to_module, from_module == to_module) ||
                is_relocation_target(to_module, to); // TODO: exports case blocks
# ifdef MONITOR_UIBP_ONLINE
            if (is_admitted) {
                from_module->unexpected_ibt.admitted_targets++;
                from_module->unexpected_ibt.admitted_target_invocations++;
                CS_LOG("UIBT| Missed export %s("PX")->%s\n",
                    from_module->module_name, MODULAR_PC(from_module, from), export.function_id);
            } else {
                from_module->unexpected_ibt.suspicious_targets++;
                from_module->unexpected_ibt.suspicious_target_invocations++;
                if (from_module == to_module)
                    CS_LOG("UIBT| Missed internal %s("PX"->"PX")\n",
                        from_module->module_name, MODULAR_PC(from_module, from), MODULAR_PC(from_module, to));
                else
                    CS_LOG("UIBT| Missed cross-module to callback %s("PX")->%s("PX")\n", from_module->module_name,
                        MODULAR_PC(from_module, from), to_module->module_name, MODULAR_PC(to_module, to));
            }
            report_unexpected_ibt(from_module);
# endif
        }

        output_lock_acquire();
        if (from_module == to_module)
            edge_index = trace_files[graph_edge_file].entry_count;
        else
            edge_index = trace_files[graph_cross_module_file].entry_count;
        output_lock_release();

        install_unexpected_ibp(dcontext, from, to, from_module, to_module,
            !IS_BB_MONITOR_MISS(from_state), !IS_BB_MONITOR_MISS(to_state), edge_index, is_admitted, is_return);
    } else
#endif
        ibp_hash_add(dcontext, from, to); // cs-todo: could skip the extra lookup by making a separate add()
}

static void
activate_trace_file(trace_file_id id, bool active, bool buffered, uint buffer_size,
                    const char *basename, const char *extension) {
    char filename[256];
    trace_file_t *trace_file = &trace_files[id];

    // buffered = false; // not yet...

    trace_file->entry_count = 0U;
    trace_file->last_buffer_flush = quick_system_time_millis();
    trace_file->active = active;
    if (active) {
        generate_filename(filename, basename, extension);
        trace_file->file = create_output_file(filename);

        CS_DET("Attempting to open filename %s: 0x%x\n", filename, trace_file->file);

        trace_file->buffered = buffered;
        if (buffered) {
            trace_file->buffer_position = 0U;
            trace_file->buffer_size = buffer_size;
            trace_file->buffer = (uint64*)CS_ALLOC(buffer_size * sizeof(uint64));
        }
    }
}

static inline void
write_byte_aligned_file_entry(trace_file_id id, uint64 data) {
    trace_file_t *output = &trace_files[id];

    assert_output_lock();
    if (output->buffered) {
        ASSERT(output->buffer_position < output->buffer_size);

        *(output->buffer + output->buffer_position) = data;
        output->buffer_position++;

        if (output->buffer_position == output->buffer_size)
            flush_trace_buffer(output);
    } else {
        dr_write_file(output->file, &data, sizeof(uint64));
    }
}

static inline void
flush_trace_buffer(trace_file_t *trace_file) {
    assert_output_lock();

    if (trace_file->buffer_position > 0) {
        ssize_t output_bytes = dr_write_file(trace_file->file, trace_file->buffer,
                                            trace_file->buffer_position * sizeof(uint64));
        if (output_bytes < 0) {
            CS_ERR("Failed to write to an output file; errno %d\n", -(int)output_bytes);
            return;
        } else if (output_bytes < (ssize_t) (trace_file->buffer_position * sizeof(uint64))) {
            CS_ERR("Failed to fully write an 8-byte value to an output file; only %d bytes were written; errno %d\n",
                output_bytes, errno);
            return;
        }
        trace_file->buffer_position = 0;
    }
    trace_file->last_buffer_flush = quick_system_time_millis();
}

static void
close_active_trace_files() {
    uint i;

	output_lock_acquire();
    for (i = 0; i < _trace_file_id_count; i++) {
        trace_file_t *trace_file = &trace_files[i];
        if (trace_file->active)
            close_active_trace_file(trace_file);
    }
	output_lock_release();
}

static void
close_active_trace_file(trace_file_t *trace_file) {
    if (trace_file->buffered) {
        flush_trace_buffer(trace_file);
        dr_global_free(trace_file->buffer, trace_file->buffer_size * sizeof(uint64));
    }
    dr_close_file(trace_file->file);
}

static inline bool
find_in_exports(IMAGE_EXPORT_DIRECTORY *exports, size_t exports_size, app_pc from, app_pc to,
    module_location_t *from_module, module_location_t *to_module, char *function_id)
{
    uint i;
    PULONG functions = (PULONG)(to_module->start_pc + exports->AddressOfFunctions);
    PUSHORT ordinals = (PUSHORT)(to_module->start_pc + exports->AddressOfNameOrdinals);
    PULONG fnames = (PULONG)(to_module->start_pc + exports->AddressOfNames);

#ifdef WATCH_TAG_ACTIVE
    if ((watch_tag == from) || (watch_tag == to)) {
        for (i = 0; i < exports->NumberOfNames; i++) {
            CS_DET("watch> %s exports %s at "PX"\n", to_module->module_name,
                (char *)((ulong)to_module->start_pc + fnames[i]),
                ((ulong)to_module->start_pc + functions[ordinals[i]]));
        }
    }
#endif

    for (i = 0; i < exports->NumberOfNames; i++) {
        if ((ulong)to == ((ulong)to_module->start_pc + functions[ordinals[i]])) {
            char *exported_name = (char *)((ulong)to_module->start_pc + fnames[i]);
            strcat(function_id, to_module->module_name);
            strcat(function_id, exported_name); // "<to-module>!<function-name>"

            CS_DET("Found export %s for edge to="PX" in the names section.\n", exported_name, to);

            return true;
        }
    }
    for (i = 0; i < exports->NumberOfFunctions; i++) {
        ulong exported = ((ulong)to_module->start_pc + functions[i]);
        uint ordinal = i+1;
        if ((exported > p2int(exports)) && (exported < (p2int(exports) + exports_size))) {
            char *exported_name = (char *)int2p(exported);
            // it's a redirect, what does it match?

            CS_DET("Found export redirect to %s in the noname section.\n", exported_name);
        } else if ((ulong)to == exported) { // it's an ordinal
            dr_snprintf(function_id, 256, "%s@ordinal(%d)", to_module->module_name, ordinal); // "<to-module>@ordinal(#)"
            // cs-todo: it may be that these need to be identified as callbacks when not explicitly imported by ordinal

            CS_DET("Found export ordinal %d for edge to="PX" in the noname section.\n", ordinal, to);

            return true;
        }
    }

    return false;
}

// deprecated: export parser has been fixed and now finds everything this section contains
/*
static inline bool
find_in_imports(app_pc from, app_pc to, module_location_t *from_module,
    module_location_t *to_module, char *function_id)
{
    IMAGE_THUNK_DATA *name_import;
    IMAGE_THUNK_DATA *address_import;
    IMAGE_IMPORT_DESCRIPTOR *module_import_section;
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY *dir;
    const char *imported_function_name;
    bool by_ordinal;
    DWORD ordinal;

    if ((from_module == &unknown_module) || (from_module->type == module_type_dynamo))
        return false;

    if (!is_readable_pe_base(from_module->start_pc)) {
        return false;
    }
    nt = NT_HEADER(from_module->start_pc);
    dir = OPT_HDR(nt, DataDirectory) + IMAGE_DIRECTORY_ENTRY_IMPORT;
    if ((dir == NULL) || (dir->Size <= 0)) {
        return false;
    }

#ifdef WATCH_TAG_ACTIVE
    if ((watch_tag == from) || (watch_tag == to)) {
        module_import_section = (IMAGE_IMPORT_DESCRIPTOR *) RVA_TO_VA(from_module->start_pc, dir->VirtualAddress);

        while (module_import_section->OriginalFirstThunk) {
            name_import = (IMAGE_THUNK_DATA *) RVA_TO_VA(from_module->start_pc, module_import_section->OriginalFirstThunk);
            address_import = (IMAGE_THUNK_DATA *) RVA_TO_VA(from_module->start_pc, module_import_section->FirstThunk);
            while (name_import->u1.Function != 0) {
                by_ordinal = CAST_TO_bool(TEST(IMAGE_ORDINAL_FLAG, name_import->u1.Function));
                if (by_ordinal) {
                    imported_function_name = "<ordinal>";
                    ordinal = name_import->u1.AddressOfData & (~IMAGE_ORDINAL_FLAG);
                } else {
                    IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)
                        RVA_TO_VA(from_module->start_pc, name_import->u1.AddressOfData);
                    imported_function_name = (const char *) by_name->Name;
                    ordinal = 0;
                }

                CS_DET("watch> %s imports %s(%d) at "PX"\n", from_module->module_name,
                    imported_function_name, ordinal, (app_pc) address_import->u1.Function);

                name_import++;
                address_import++;
            }
            module_import_section++;
        }
    }
#endif

    module_import_section = (IMAGE_IMPORT_DESCRIPTOR *) RVA_TO_VA(from_module->start_pc, dir->VirtualAddress);

    while (module_import_section->OriginalFirstThunk) {
        name_import = (IMAGE_THUNK_DATA *) RVA_TO_VA(from_module->start_pc, module_import_section->OriginalFirstThunk);
        address_import = (IMAGE_THUNK_DATA *) RVA_TO_VA(from_module->start_pc, module_import_section->FirstThunk);
        while (name_import->u1.Function != 0) {
            by_ordinal = CAST_TO_bool(TEST(IMAGE_ORDINAL_FLAG, name_import->u1.Function));
            if (by_ordinal) {
                imported_function_name = "<ordinal>";
                ordinal = name_import->u1.AddressOfData & (~IMAGE_ORDINAL_FLAG);
            } else {
                IMAGE_IMPORT_BY_NAME *by_name = (IMAGE_IMPORT_BY_NAME *)
                    RVA_TO_VA(from_module->start_pc, name_import->u1.AddressOfData);
                imported_function_name = (const char *) by_name->Name;
                ordinal = 0;
            }

            if (((app_pc) address_import->u1.Function) == to) {
                CS_DET("Callback %s("PX") calls imported function %s(%d) at %s("PX")\n",
                    from_module->module_name, from, imported_function_name, ordinal,
                    to_module->module_name, to);
                strcat(function_id, imported_function_name);
                return true;
            }

            name_import++;
            address_import++;
        }
        module_import_section++;
    }

    return false;
}
*/

// deprecated: export parser has been fixed and now finds everything in the dynamic imports
/*
static inline bool
find_in_dynamic_imports(app_pc to, char *function_id) {
    uint j;

#ifdef WATCH_TAG_ACTIVE
    if ((watch_tag == from) || (watch_tag == to)) {
        for (j = 0; j < resolved_imports->entries; j++) {
            resolved_import_t *import = drvector_get_entry(resolved_imports, j);
            CS_DET("watch> GetProcAddress returned "PX" for %s\n",
                import->address, import->name);
        }
    }
#endif

   // cs-todo: lock it!
    for (j = 0; j < resolved_imports->entries; j++) {
        resolved_import_t *import = drvector_get_entry(resolved_imports, j);
        if (import->address == to) {
            strcat(function_id, import->name);

            CS_DET("Dynamically resolved import of %s\n", import->name);

            return true;
        }
    }
}
*/

static inline char*
get_cross_module_name(module_location_t *module) {
    if (module->type == module_type_image)
        return module->module_name;
    else
        return "<anonymous>"; // represents any dynamically allocated module
}

static inline byte
get_black_box_callout_ordinal(graph_edge_type edge_type) {
    switch (edge_type) {
        case indirect_edge:
            return 0;
        case direct_edge:
            return 1;
        case unexpected_return_edge:
            return 2;
        default:
            return default_edge_ordinal(edge_type); /* very strange */
    }
    ASSERT(false);
    return 0;
}

static inline incoming_edge_t*
create_pending_edge(app_pc from, byte exit_ordinal, graph_edge_type type, ushort module_instance_hash) {
    incoming_edge_t *edge = (incoming_edge_t *)CS_ALLOC(sizeof(incoming_edge_t));
    edge->from = from;
    edge->exit_ordinal = exit_ordinal;
    edge->type = type;
    edge->module_instance_hash = module_instance_hash;
    return edge;
}

static void
free_incoming_edge(void *edge) {
    dr_global_free(edge, sizeof(incoming_edge_t));
}
