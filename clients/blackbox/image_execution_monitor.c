#include "execution_monitor.h"
//#include "../../core/options.h"
//#include "../../core/x86/instrument.h"
#include "indirect_link_hashtable.h"

/**** Private Fields ****/

#define MON_WARN(...) CS_WARN("MON| "__VA_ARGS__)
#define MON_LOG(...) CS_DET("MON| "__VA_ARGS__)
#define MON_DET(...) CS_DET("MON| "__VA_ARGS__)

#pragma pack(push, 4)

typedef struct monitor_bb_t monitor_bb_t;
struct monitor_bb_t {
    uint counts; // lo-bit { IMIBT (1) | IM (11) | CS (12) | E (8) } hi-bit
    bb_hash_t hash;
    uint edges[1]; // fake array size: it's specified in `counts`
}; // IMIBT = Intra Module Indirect Branch Target

typedef struct monitor_bb_index_t monitor_bb_index_t;
struct monitor_bb_index_t {
    uint relative_tag;
    uint data_offset;
};

  /**** Vector Template � monitor_bb_index_vector_t ****/

#define VECTOR_NAME_KEY monitor_bb_index_vector
#define VECTOR_ENTRY_TYPE monitor_bb_index_t
#define VECTOR_COMPARISON_TYPE uint
#define VECTOR_ALLOWS_DUPLICATES 1
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvector.h"

#define VECTOR_NAME_KEY monitor_bb_index_vector
#define VECTOR_ENTRY_TYPE monitor_bb_index_t
#define VECTOR_COMPARISON_TYPE uint
#define VECTOR_ALLOWS_DUPLICATES 1
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvectorx.h"

typedef struct module_dataset_t module_dataset_t;
struct module_dataset_t {
    uint name_offset;
    uint index_offset;
};

  /**** Vector Template � module_dataset_vector_t ****/

#define VECTOR_NAME_KEY module_dataset_vector
#define VECTOR_ENTRY_TYPE module_dataset_t
#define VECTOR_COMPARISON_TYPE char*
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvector.h"

#define VECTOR_NAME_KEY module_dataset_vector
#define VECTOR_ENTRY_TYPE module_dataset_t
#define VECTOR_COMPARISON_TYPE char*
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvectorx.h"

alarm_data_t *alarm_counters;
alarm_data_t *alarm_limits;

static struct dataset_t {
    bool active;
    uint offset;
    size_t size;
    module_dataset_vector_t modules;
} dataset;

#pragma pack(pop)

  /**** Multimap Template � callout_multimap_t ****/

#define MULTIMAP_KEY_TYPE bb_hash_t
#define MULTIMAP_VALUE_TYPE app_pc
#define MULTIMAP_NAME_KEY callout_multimap
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_KEY_TYPE bb_hash_t
#define MULTIMAP_VALUE_TYPE app_pc
#define MULTIMAP_NAME_KEY callout_multimap
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimapx.h"

  /**** Multimap Template � export_multimap_t ****/

#define MULTIMAP_KEY_TYPE bb_hash_t
#define MULTIMAP_VALUE_TYPE app_pc
#define MULTIMAP_NAME_KEY export_multimap
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_KEY_TYPE bb_hash_t
#define MULTIMAP_VALUE_TYPE app_pc
#define MULTIMAP_NAME_KEY export_multimap
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimapx.h"

  /**** Interpreting Accessors ****/

#define MODULE_NAME(module) ((char*)int2p(dataset.offset + module.name_offset))
#define BB_DATA(bb_index) ((monitor_bb_t*)int2p(dataset.offset + bb_index->data_offset))
#define GET_BB_INDEX(module, relative_tag) \
    monitor_bb_index_vector_search((monitor_bb_index_vector_t*)module->monitor_data, relative_tag)

#define GET_RELATIVE_TAG(module, tag) (p2int(tag) - p2int(module->start_pc))
#define GET_ABSOLUTE_TAG(module, relative_tag) int2p(p2int(module->start_pc) + p2int(relative_tag))

#define GET_INTRA_MODULE_COUNT(from_data) ((from_data->counts >> 1) & 0x7ff)
#define GET_INTRA_MODULE_TO(from_data, i) (from_data->edges[i] & 0xfffffff)
#define GET_INTRA_MODULE_ORDINAL(from_data, i) (from_data->edges[i] >> 0x1c)
#define IS_INTRA_MODULE_IBT(from_data) (from_data->counts & 1)

#define GET_CALLOUT_SITE_COUNT(from_data) ((from_data->counts >> 0xc) & 0xfff)
#define GET_FIRST_CALLOUT_SITE_HASH(from_data) ((bb_hash_t*)(&from_data->edges[GET_INTRA_MODULE_COUNT(from_data)]))

#define GET_EXPORT_COUNT(to_data) (to_data->counts >> 0x18)
#define GET_FIRST_EXPORT_HASH(to_data) (GET_FIRST_CALLOUT_SITE_HASH(to_data) + GET_CALLOUT_SITE_COUNT(to_data))

#define GET_BB_DATA_SIZE(bb) (4 /*counts*/ + 8 /*hash*/ + (GET_INTRA_MODULE_COUNT(bb) * 4) + \
    (GET_CALLOUT_SITE_COUNT(bb) * 8) + (GET_EXPORT_COUNT(bb) * 8))
#define GET_MODULE_INDEX_SIZE(module_index_offset) (*(uint*)int2p(dataset.offset + module_index_offset))
#define GET_MODULE_INDEX(module_index_offset) ((monitor_bb_index_t*)int2p(dataset.offset + module_index_offset + 4))

static callout_multimap_t *callout_multimap;
static export_multimap_t *export_multimap;

  /**** Miss Reports ****/

// parallel enums:
enum miss_type {
    node_miss = 1,
    edge_miss = 2,
    cross_module_edge_miss = 4,
    anonymous_node_miss = 8,
    anonymous_edge_miss = 0x10,
    white_box_entry_miss = 0x20,
    white_box_exit_miss = 0x40,
    black_box_entry_miss = 0x80,
    black_box_exit_miss = 0x100,
    last_miss_type = 0x8000
};

enum miss_type_index {
    node_miss_index,
    edge_miss_index,
    cross_module_edge_miss_index,
    anonymous_node_miss_index,
    anonymous_edge_miss_index,
    white_box_entry_miss_index,
    white_box_exit_miss_index,
    black_box_entry_miss_index,
    black_box_exit_miss_index,
    last_miss_type_index
};

typedef struct miss_type_count_t miss_type_count_t;
struct miss_type_count_t {
    uint counts[last_miss_type_index];
    report_mask_t node_report_mask;
    report_mask_t edge_report_mask;
} *miss_type_counts;

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
# define VECTOR_NAME_KEY unrecognized_subgraph_vector
# define VECTOR_ENTRY_TYPE app_pc
# define VECTOR_ENTRY_INLINE 1
# include "../drcontainers/drvector.h"

# define VECTOR_NAME_KEY unrecognized_subgraph_vector
# define VECTOR_ENTRY_TYPE app_pc
# define VECTOR_ENTRY_INLINE 1
# include "../drcontainers/drvectorx.h"

typedef struct unrecognized_subgraph_t unrecognized_subgraph_t;
struct unrecognized_subgraph_t /* extends miss_type_count_t */ {
    uint counts[last_miss_type_index];
    unrecognized_subgraph_vector_t *tags;
    char *label;
    ushort id;
};

static hashtable_t *unrecognized_subgraphs;
#endif

static bool *monitor_exited = NULL;

#define NODE_MISS_REPORT_MASK 0x3f
#define EDGE_MISS_REPORT_MASK 0x7f

#define MISS_COUNT(count_data, miss_type) count_data->counts[miss_type##_index]

/**** Private Prototypes ****/

static void
init_dataset();

static bool
verify_black_box_entry(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash);

static bool
verify_black_box_exit(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash);

static void
report_node_miss(bb_state_t *state, bool is_anonymous);

static void
report_edge_miss(dcontext_t *dcontext, uint type_flags, app_pc from, app_pc to, bb_state_t *from_state,
    bb_state_t *to_state, module_location_t *to_module);

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
static void
merge_left_subgraph_into_right(unrecognized_subgraph_t *left, unrecognized_subgraph_t *right);
#endif

static void
report_miss_totals(char *label, miss_type_count_t *c);

static int
module_id_comparator(module_dataset_t module, char *module_id);

static int
relative_tag_comparator(monitor_bb_index_t index, uint relative_tag);

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
static unrecognized_subgraph_t*
create_unrecognized_subgraph(module_location_t *module);

static void
destroy_unrecognized_subgraph(unrecognized_subgraph_t *subgraph);
#endif

/**** Public Functions ****/

void
init_execution_monitor() {
    uint anonymous_module_offset = 0; // assigned on success, when anonymous data exists

    monitor_exited = CS_ALLOC(sizeof(bool));
    *monitor_exited = false;

    if (CROWD_SAFE_MONITOR()) {
        uint i, test;
        miss_type_counts = (miss_type_count_t *)CS_ALLOC(sizeof(miss_type_count_t));
        for (i = 0, test = 1; test < last_miss_type; i++, test <<= 1) {
            miss_type_counts->counts[i] = 0;
        }
        init_report_mask(&miss_type_counts->node_report_mask, 0xf, 0xffffffff);
        init_report_mask(&miss_type_counts->edge_report_mask, 0x1f, 0xffffffff);

        init_dataset();

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
        unrecognized_subgraphs = (hashtable_t *)CS_ALLOC(sizeof(hashtable_t)); // cs-todo: cleanup
        hashtable_init_ex(
            unrecognized_subgraphs,
            9, // key size
            HASH_INTPTR,
            false,
            false,
            NULL, // cs-todo: free func for cleanup
            NULL, /* no custom hashing */
            NULL);
#endif
    }

    if (dataset.active) {
        uint alarm_data_offset;
        uint last_module_offset = dataset.modules.array[dataset.modules.entries-1].index_offset;
        uint last_module_entry_count = GET_MODULE_INDEX_SIZE(last_module_offset);
        monitor_bb_index_t *last_module_index = GET_MODULE_INDEX(last_module_offset);
        anonymous_module_offset = p2int(&last_module_index[last_module_entry_count]);
        alarm_data_offset = init_anonymous_execution_monitor(anonymous_module_offset);

        if (CROWD_SAFE_ALARM()) {
            alarm_limits = (alarm_data_t *)alarm_data_offset;
            alarm_counters = CS_ALLOC(sizeof(alarm_data_t));
            memset(alarm_counters, 0, sizeof(alarm_data_t));
        }
    } else {
        init_anonymous_execution_monitor(0);
    }

    get_monitor_module(&system_module);
}

bool
is_monitor_active() {
    return dataset.active;
}

void
get_monitor_module(module_location_t *module) {
    char module_id[256] = {0};
    module_dataset_t *data;

    if (!dataset.active) {
        module->monitor_data = NULL;
        return;
    }

    if (module == &system_module)
        strcat(module_id, "__system");
    else
        print_module_id(module_id, 256, module);

    data = module_dataset_vector_search(&dataset.modules, module_id);
    if (data == NULL) {
        CS_LOG("No monitor data for module %s\n", module_id);

        module->monitor_data = NULL;
    } else {
        // cs-todo: if the module has been loaded once already, copy from there

        monitor_bb_index_vector_t *monitor_data = (monitor_bb_index_vector_t*)CS_ALLOC(sizeof(monitor_bb_index_vector_t));
        memset(monitor_data, 0, sizeof(monitor_bb_index_vector_t));
        monitor_data->entries = GET_MODULE_INDEX_SIZE(data->index_offset);
        monitor_data->array = GET_MODULE_INDEX(data->index_offset);
        monitor_data->comparator = relative_tag_comparator;

        module->monitor_data = (monitor_module_data_t*)monitor_data;
    }
}

void
free_monitor_module(module_location_t *module) {
    if (!dataset.active)
        return;

    if (module->monitor_data != NULL)
        dr_global_free(module->monitor_data, sizeof(monitor_bb_index_vector_t));
}

bool
verify_basic_block(dcontext_t *dcontext, module_location_t *module, app_pc tag, bb_state_t *state) {
    uint relative_tag;
    bool matched = false;
    monitor_bb_index_t *index;

    assert_hashcode_lock();

    if (*monitor_exited)
        return true;
    if (!dataset.active)
        return false;

    if (module->type == module_type_anonymous) {
        if (!verify_anonymous_block(module, state->hash)) {
            report_node_miss(state, true);
            return false;
        } else {
            return true;
        }
    }

    if (module->monitor_data == NULL) {
        MON_LOG("<miss %s("PX")> No monitor data for module %s. Can't verify bb.\n", module->module_name,
            tag, module->module_name);
        report_node_miss(state, false);
        return false;
    }

    relative_tag = GET_RELATIVE_TAG(module, tag);
    index = GET_BB_INDEX(module, relative_tag);
    if (index == NULL) {
        MON_LOG("<miss %s("PX")> Cannot find bb data\n", module->module_name, relative_tag);
        report_node_miss(state, false);
        return false;
    }

    for (; index->relative_tag == relative_tag; index++) {
        monitor_bb_t *data = BB_DATA(index);
        uint i, j, edge_count = GET_INTRA_MODULE_COUNT(data);
        export_multimap_entry_t *export_entry;
        callout_multimap_entry_t *callout_entry;
        bb_hash_t *cross_module_hash;
        app_pc endpoint;

        if (data->hash == state->hash) {
            matched = true;
#ifndef MONITOR_ALL_IBP
            for (i = 0; i < edge_count; i++) {
                // cs-todo: filter by edge type: indirect only!
                ibp_hash_add(dcontext, tag, GET_ABSOLUTE_TAG(module, GET_INTRA_MODULE_TO(data, i)));
            }
#endif
        } else {
            continue;

            //MON_LOG("<miss %s("PX")> Failed to verify bb: the hash is wrong!\n", module->module_name, relative_tag);
            // ok to still add the expected IBP edges?
            //return false;
        }

        edge_count = GET_CALLOUT_SITE_COUNT(data);
        cross_module_hash = GET_FIRST_CALLOUT_SITE_HASH(data);
        for (i = 0; i < edge_count; i++, cross_module_hash++) {
            export_entry = export_multimap_lookup(export_multimap, *cross_module_hash);
            for (j = 0; j < export_multimap_item_count(export_entry); j++) {
                endpoint = export_multimap_entry_get_item(export_entry, j);
#ifndef MONITOR_ALL_IBP
                ibp_hash_add(dcontext, tag, endpoint);
#endif

                MON_DET("Expecting cross-module edge %s("PX") -> "PX"\n",
                    module->module_name, relative_tag, endpoint);
            }

            MON_DET("Adding tag "PX" to callouts\n", tag);
            callout_multimap_add(callout_multimap, *cross_module_hash, tag);
        }

        edge_count = GET_EXPORT_COUNT(data);
        // cross_module_hash = GET_FIRST_EXPORT_HASH(data); // already there
        for (i = 0; i < edge_count; i++, cross_module_hash++) {
            callout_entry = callout_multimap_lookup(callout_multimap, *cross_module_hash);
            for (j = 0; j < callout_multimap_item_count(callout_entry); j++) {
                endpoint = callout_multimap_entry_get_item(callout_entry, j);
#ifndef MONITOR_ALL_IBP
                ibp_hash_add(dcontext, endpoint, tag);
#endif

                MON_DET("Expecting cross-module edge "PX" -> %s("PX")\n",
                   endpoint, module->module_name, relative_tag);
            }

            MON_DET("Adding tag "PX" to exports\n", tag);
            export_multimap_add(export_multimap, *cross_module_hash, tag);
        }
    }

    if (!matched)
        report_node_miss(state, false);

    return matched;
}

// cs-todo: hook bb removal and clear entries from `callout_multimap` and `export_multimap`

bool
verify_intra_module_edge(dcontext_t *dcontext, module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
    bb_state_t *from_state, bb_state_t *to_state, byte exit_ordinal, graph_edge_type edge_type)
{
    uint relative_from, relative_to;
    monitor_bb_index_t *from_index;

    assert_hashcode_lock();

    if (*monitor_exited)
        return true;
    if (!dataset.active)
        return false;

    if (from_module->type == module_type_anonymous) {
        if (!verify_anonymous_edge(dcontext, from_module, from, to, to_state->hash, exit_ordinal, edge_type)) {
            report_edge_miss(dcontext, anonymous_edge_miss, from, to, from_state, to_state, to_module);
            return false;
        } else {
            return true;
        }
    }

    if (from_module->monitor_data == NULL) {
        MON_DET("No monitor data for module %s. Can't verify edge "PX" -> "PX"\n", from_module->module_name, from, to);
        return false;
    }

    relative_from = GET_RELATIVE_TAG(from_module, from);
    from_index = GET_BB_INDEX(from_module, relative_from);
    relative_to = GET_RELATIVE_TAG(to_module, to);

    if (from_index == NULL) {
        MON_LOG("<miss %s("PX")> Cannot find bb data.\n", from_module->module_name, relative_from);
        report_edge_miss(dcontext, 0, from, to, from_state, to_state, to_module);
        return false;
    }

    for (; from_index->relative_tag == relative_from; from_index++) {
        monitor_bb_t *from_data = BB_DATA(from_index);
        uint i, edge_count = GET_INTRA_MODULE_COUNT(from_data);

        MON_DET("Checking %d edges for %s("PX" -> "PX")\n",
            edge_count, from_module->module_name, relative_from, relative_to);

        for (i = 0; i < edge_count; i++) {

            MON_DET("\tHave edge to "PX"\n", GET_INTRA_MODULE_TO(from_data, i), relative_to);

            if ((GET_INTRA_MODULE_TO(from_data, i) == relative_to) &&
                    (GET_INTRA_MODULE_ORDINAL(from_data, i) == exit_ordinal)) {
                if ((edge_type != direct_edge) && (edge_type != call_continuation_edge)) {
                    MON_DET("<ibp %s("PX" -> "PX")> Warning: verified an unexpected edge of type %d.\n",
                        from_module->module_name, relative_from, relative_to, edge_type);
                }
                return true;
            }
        }
    }

    MON_LOG("<miss %s("PX" -> "PX")> Could not find the %s edge on thread 0x%x!\n",
        from_module->module_name, relative_from, relative_to, edge_type_string(edge_type), current_thread_id());
    report_edge_miss(dcontext, 0, from, to, from_state, to_state, to_module);
    return false;
}

bool
verify_cross_module_edge(dcontext_t *dcontext, module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
    bb_state_t *from_state, bb_state_t *to_state, bb_hash_t edge_hash, graph_edge_type edge_type)
{
    uint relative_from, relative_to;
    monitor_bb_index_t *from_index, *to_index;
    bool callout_verified = false;

    assert_hashcode_lock();

    if (*monitor_exited)
        return true;
    if (!dataset.active)
        return false;

    relative_from = GET_RELATIVE_TAG(from_module, from);
    relative_to = GET_RELATIVE_TAG(to_module, to);

    if (from_module->type == module_type_anonymous) {
        if (IS_BB_BLACK_BOX(from_state)) {
            if (!verify_black_box_exit(from_module, to_module, from, to, edge_hash)) {
                report_edge_miss(dcontext, cross_module_edge_miss | anonymous_edge_miss | black_box_exit_miss,
                    from, to, from_state, to_state, to_module);
                return false;
            } else {
                return true;
            }
        } else {
            if (!verify_anonymous_exit_point(from_module, to_module, from, to, edge_hash)) {
                report_edge_miss(dcontext, cross_module_edge_miss | anonymous_edge_miss | white_box_exit_miss,
                    from, to, from_state, to_state, to_module);
                return false;
            } else {
                return true;
            }
        }
    }

    if (from_module->monitor_data == NULL) {
        MON_LOG("<miss %s("PX") -> %s("PX")> No monitor data for module %s. Can't verify the edge.\n",
            from_module->module_name, relative_from, to_module->module_name, relative_to, from_module->module_name);
        report_edge_miss(dcontext, cross_module_edge_miss, from, to, from_state, to_state, to_module);
        return false;
    }

    if (to_module->type == module_type_anonymous) {
        if (IS_BB_BLACK_BOX(to_state)) {
            if (!verify_black_box_entry(from_module, to_module, from, to, to_state->hash, edge_hash)) {
                report_edge_miss(dcontext, cross_module_edge_miss | anonymous_edge_miss | black_box_entry_miss,
                    from, to, from_state, to_state, to_module);
                return false;
            } else {
                return true;
            }
        } else {
            if (!verify_anonymous_entry_point(from_module, to_module, from, to, to_state->hash, edge_hash, edge_type)) {
                report_edge_miss(dcontext, cross_module_edge_miss | anonymous_edge_miss | white_box_entry_miss,
                    from, to, from_state, to_state, to_module);
                return false;
            } else {
                return true;
            }
        }
    }

    from_index = GET_BB_INDEX(from_module, relative_from);

    if (from_index == NULL) {
        MON_LOG("<miss %s("PX") -> %s("PX")> Cannot find bb data for the 'from' node.\n",
            from_module->module_name, relative_from, to_module->module_name, relative_to);
        report_edge_miss(dcontext, cross_module_edge_miss, from, to, from_state, to_state, to_module);
        return false;
    }

    for (; (from_index->relative_tag == relative_from) && !callout_verified; from_index++) {
        monitor_bb_t *from_data = BB_DATA(from_index);
        uint i, edge_count = GET_CALLOUT_SITE_COUNT(from_data);
        bb_hash_t *callout_hash = GET_FIRST_CALLOUT_SITE_HASH(from_data);
        for (i = 0; i < edge_count; i++, callout_hash++) {
            if (*callout_hash == edge_hash) {
                if (edge_type != direct_edge) {
                    MON_DET("Cross-module callout %s("PX") -> %s("PX") was not preloaded\n",
                       from_module->module_name, relative_from, to_module->module_name, relative_to);
                }
                callout_verified = true;
                break;
            }
        }
    }

    if (!callout_verified) {
        MON_LOG("<miss %s("PX") -> %s("PX")> Could not find the cross-module callout hash for the 'from' node!\n",
            from_module->module_name, relative_from, to_module->module_name, relative_to);
        report_edge_miss(dcontext, cross_module_edge_miss, from, to, from_state, to_state, to_module);
        return false;
    }

    to_index = GET_BB_INDEX(to_module, relative_to);

    if (to_index == NULL) {
        MON_LOG("<miss %s("PX") -> %s("PX")> Cannot find bb data for the 'to' node.\n",
            from_module->module_name, relative_from, to_module->module_name, relative_to);
        report_edge_miss(dcontext, cross_module_edge_miss, from, to, from_state, to_state, to_module);
        return false;
    }

    for (; to_index->relative_tag == relative_to; to_index++) {
        monitor_bb_t *to_data = BB_DATA(to_index);
        uint i, edge_count = GET_EXPORT_COUNT(to_data);
        bb_hash_t *export_hash = GET_FIRST_EXPORT_HASH(to_data);
        for (i = 0; i < edge_count; i++, export_hash++) {
            if (*export_hash == edge_hash) {
                if (edge_type != direct_edge) {
                    MON_DET("Cross-module export %s("PX") -> %s("PX") was not preloaded\n",
                       from_module->module_name, relative_from, to_module->module_name, relative_to);
                }
                return true;
            }
        }
    }

    MON_LOG("<miss %s("PX") -> %s("PX")> Could not find the cross-module export hash for the 'to' node of type %s!\n",
        from_module->module_name, relative_from, to_module->module_name, relative_to, edge_type_string(edge_type));
    report_edge_miss(dcontext, cross_module_edge_miss, from, to, from_state, to_state, to_module);
    return false;
}

bool
find_unexpected_ibt_precedent(app_pc ibt, module_location_t *ibt_module, bool is_cross_module) {
    if (dataset.active && (ibt_module->monitor_data != NULL)) {
        uint relative_ibt = GET_RELATIVE_TAG(ibt_module, ibt);
        monitor_bb_index_t *ibt_index = GET_BB_INDEX(ibt_module, relative_ibt);

        if (ibt_index != NULL) {
            monitor_bb_t *ibt_data = BB_DATA(ibt_index);

            if (is_cross_module)
                return (GET_EXPORT_COUNT(ibt_data) > 0);
            else
                return IS_INTRA_MODULE_IBT(ibt_data);
        }
    }
    return false;
}

bool
is_abnormal_return(module_location_t *return_bb_module, app_pc return_bb_tag) {
    if (dataset.active && (return_bb_module->monitor_data != NULL)) {
        uint relative_tag = GET_RELATIVE_TAG(return_bb_module, return_bb_tag);
        monitor_bb_index_t *return_bb_index = GET_BB_INDEX(return_bb_module, relative_tag);

        if (return_bb_index != NULL) {
            monitor_bb_t *return_bb_data = BB_DATA(return_bb_index);
            return GET_CALLOUT_SITE_COUNT(return_bb_data) > 0 || GET_INTRA_MODULE_COUNT(return_bb_data) > 0;
        }
    }
    return false;
}

bool
is_spurious_unexpected_return(module_location_t *return_bb_module, app_pc return_bb_tag) {
    if (dataset.active && (return_bb_module->monitor_data != NULL)) {
        uint relative_tag = GET_RELATIVE_TAG(return_bb_module, return_bb_tag);
        monitor_bb_index_t *return_bb_index = GET_BB_INDEX(return_bb_module, relative_tag);

        if (return_bb_index != NULL) {
            monitor_bb_t *return_bb_data = BB_DATA(return_bb_index);
            CS_LOG("BL| Monitored UR site is abnormal: %d outgoing edges\n",
                   GET_CALLOUT_SITE_COUNT(return_bb_data) + GET_INTRA_MODULE_COUNT(return_bb_data));
            return GET_CALLOUT_SITE_COUNT(return_bb_data) == 0 && GET_INTRA_MODULE_COUNT(return_bb_data) == 0;
        }
    }
    return false;
}

void
raise_alarm(dcontext_t *dcontext, uint predicate_index, uint counter, uint limit) {
    extern alarm_type_t alarm_type;

    CS_LOG("ALARM| predicate #%d: %d >= %d\n", predicate_index, counter, limit);

    switch (alarm_type) {
        case ALARM_EXCEPTION:
            throw_app_exception(dcontext);
            break;
        case ALARM_NOTIFY_AND_EXIT:
            CS_LOG("(popup alarm message not implemented yet)\n");
            break;
    }
}

void
close_execution_monitor() {
    if (CROWD_SAFE_MONITOR() && monitor_exited != NULL && !*monitor_exited) {
        //CS_LOG("Disabling execution monitor at process exit\n");
        *monitor_exited = true;

        //CS_FREE(miss_type_counts, sizeof(miss_type_count_t));

        free_monitor_module(&system_module);

        if (dataset.active) {
            callout_multimap_delete(callout_multimap);
            dr_global_free(callout_multimap, sizeof(callout_multimap_t));

            export_multimap_delete(export_multimap);
            dr_global_free(export_multimap, sizeof(export_multimap_t));
        }
    }
}

/**** Private Functions ****/

static inline void
init_dataset() {
    extern char *monitor_dataset_path;
    uint64 file_size;
    file_t dataset_file;

    dataset.active = false; // toggle on success, below
    dataset.offset = dataset.size = 0;

    MON_DET("Opening monitor dataset file %s\n", monitor_dataset_path);

    dataset_file = dr_open_file(monitor_dataset_path, DR_FILE_READ);
    if (dataset_file == INVALID_FILE) {
        MON_WARN("Failed to open the monitor dataset file %s!\n", monitor_dataset_path);
        return;
    }

    MON_DET("Loading monitor dataset %s\n", monitor_dataset_path);

    dr_file_size(dataset_file, &file_size);

    if (file_size == 0ULL) {
        MON_WARN("Failed to query the size of monitor dataset file %s\n", monitor_dataset_path);
        return;
    }

    dataset.size = (size_t) file_size;
    dataset.offset = p2int(dr_map_file(dataset_file, &dataset.size, 0ULL, PC(0),
        DR_MEMPROT_READ, 0UL)); // cs-todo: will this mess around with the disk?

    if (dataset.offset == p2int(NULL)) {
        MON_WARN("Failed to load monitor dataset %s!\n", monitor_dataset_path);
        return;
    }

    // not a MON_LOG -- always show this
    CS_LOG("Loaded 0x%lx bytes of monitor dataset file %s\n", dataset.size, monitor_dataset_path);

    dataset.active = true;
    dataset.modules.array = (module_dataset_t*)int2p(dataset.offset);
    dataset.modules.entries = (dataset.modules.array[0].name_offset / sizeof(module_dataset_t));
    dataset.modules.comparator = module_id_comparator;

    callout_multimap = (callout_multimap_t *)CS_ALLOC(sizeof(callout_multimap_t));
    callout_multimap_init(callout_multimap, NULL, "monitor callout map");

    export_multimap = (export_multimap_t *)CS_ALLOC(sizeof(export_multimap_t));
    export_multimap_init(export_multimap, NULL, "monitor export map");
}

static bool
verify_black_box_entry(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash)
{
    if (verify_black_box_export(from_module, to_module, from, to, to_hash, edge_hash)) {
        uint relative_from = GET_RELATIVE_TAG(from_module, from);
        monitor_bb_index_t *from_index = GET_BB_INDEX(from_module, relative_from);

        if (from_index == NULL) {
            MON_LOG("<miss %s("PX") -> %s("PX")> Cannot find bb data for the 'from' node.\n",
                from_module->module_name, relative_from, to_module->module_name, to);
            return false;
        }

        for (; from_index->relative_tag == relative_from; from_index++) {
            monitor_bb_t *from_data = BB_DATA(from_index);
            uint i, edge_count = GET_CALLOUT_SITE_COUNT(from_data);
            bb_hash_t *callout_hash = GET_FIRST_CALLOUT_SITE_HASH(from_data);
            for (i = 0; i < edge_count; i++, callout_hash++) {
                if (*callout_hash == edge_hash) {
                    MON_DET("<hit %s("PX") -> %s("PX")> Callout to black box found.\n",
                        from_module->module_name, relative_from, to_module->module_name, to);
                    return true;
                }
            }
        }

        MON_LOG("<miss %s("PX") -> %s("PX")> Can't verify call to black box because "
            "the call site does not target the black box.\n",
            from_module->module_name, from, to_module->module_name, to, edge_hash);
    }

    return false;
}

static bool
verify_black_box_exit(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash)
{
    if (verify_black_box_callout(from_module, to_module, from, to, edge_hash)) {
        uint relative_to = GET_RELATIVE_TAG(to_module, to);
        monitor_bb_index_t *to_index = GET_BB_INDEX(to_module, relative_to);

        if (to_index == NULL) {
            MON_LOG("<miss %s("PX") -> %s("PX")> Cannot find bb data for the 'to' node.\n",
                from_module->module_name, from, to_module->module_name, relative_to);
            return false;
        }

        for (; to_index->relative_tag == relative_to; to_index++) {
            monitor_bb_t *to_data = BB_DATA(to_index);
            uint i, edge_count = GET_EXPORT_COUNT(to_data);
            bb_hash_t *export_hash = GET_FIRST_EXPORT_HASH(to_data);
            for (i = 0; i < edge_count; i++, export_hash++) {
                if (*export_hash == edge_hash) {
                    MON_DET("<hit %s("PX") -> %s("PX")> Callout from black box found.\n",
                        from_module->module_name, from, to_module->module_name, relative_to);
                    return true;
                }
            }
        }

        MON_LOG("<miss %s("PX") -> %s("PX")> Can't verify black box callout because "
            "the call target does not export to the black box.\n",
            from_module->module_name, from, to_module->module_name, to, edge_hash);
    }
    return false;
}

static void
report_node_miss(bb_state_t *state, bool is_anonymous) {
    miss_type_counts->counts[node_miss_index]++;
    if (is_anonymous)
        miss_type_counts->counts[anonymous_node_miss_index]++;

    if (is_report_threshold(&miss_type_counts->node_report_mask, miss_type_counts->counts[node_miss_index])) {
        report_miss_totals("Totals", miss_type_counts);
    }

    SET_BB_MONITOR_MISS(state);
}

static void
report_edge_miss(dcontext_t *dcontext, uint type_flags, app_pc from, app_pc to, bb_state_t *from_state,
    bb_state_t *to_state, module_location_t *to_module)
{
    uint i, test;
    bool was_to_miss_already_known = IS_BB_MONITOR_MISS(to_state);
#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
    unrecognized_subgraph_t *miss_subgraph = NULL; // increment counts for this subgraph, if any
#endif
    if (!IS_BB_MONITORED(to_state)) {
        verify_basic_block(dcontext, to_module, to, to_state);
        SET_BB_MONITORED(to_state);
    }

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
    // cs-todo: anon->anon is *not* cross-module in this evaluation
    if (((type_flags & cross_module_edge_miss) == 0) && IS_BB_MONITOR_MISS(from_state)) { // `from` is in this module and is missing
        unrecognized_subgraph_t *continuable_subgraph = hashtable_lookup(unrecognized_subgraphs, from);
        miss_subgraph = continuable_subgraph;
        if (IS_BB_MONITOR_MISS(to_state)) {
            if (was_to_miss_already_known) {
                unrecognized_subgraph_t *merged_subgraph = hashtable_lookup(unrecognized_subgraphs, to);
                if (continuable_subgraph != merged_subgraph) {
                    if (continuable_subgraph->tags->entries > merged_subgraph->tags->entries) {
                        unrecognized_subgraph_t *swap = merged_subgraph;
                        merged_subgraph = continuable_subgraph;
                        continuable_subgraph = swap;
                    }
                    merge_left_subgraph_into_right(continuable_subgraph, merged_subgraph);
                } // else just increment the edge counts below
                miss_subgraph = merged_subgraph;
            } else {
                unrecognized_subgraph_vector_append(continuable_subgraph->tags, to);
                hashtable_add(unrecognized_subgraphs, to, continuable_subgraph);
            }
        }
    } else { // `from` is verified or a module entry
        if (IS_BB_MONITOR_MISS(to_state)) {
            if (was_to_miss_already_known) {
                miss_subgraph = hashtable_lookup(unrecognized_subgraphs, to);
            } else {
                miss_subgraph = create_unrecognized_subgraph(to_module);
                hashtable_add(unrecognized_subgraphs, to, miss_subgraph);
                unrecognized_subgraph_vector_append(miss_subgraph->tags, to);
            }
        } else { // missed an edge between verified nodes--just increment the totals
            if ((to_module->type == module_type_image) && ((type_flags & cross_module_edge_miss) == 0)) {
                to_module->intra_module_singleton_edge_misses++;
                if ((to_module->intra_module_singleton_edge_misses & 0xf) == 0)
                    MON_WARN("Missed %d singleton edges in %s\n", to_module->intra_module_singleton_edge_misses, to_module->module_name);
            }
        }
    }
#endif

    miss_type_counts->counts[edge_miss_index]++;
#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
    if (miss_subgraph != NULL) {
        miss_subgraph->counts[edge_miss_index]++;
        miss_subgraph->counts[node_miss_index] = miss_subgraph->tags->entries;
    }
#endif
    for (i = 0, test = 1; test < last_miss_type; i++, test <<= 1) {
        if ((type_flags & test) > 0) {
            miss_type_counts->counts[i]++;
#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
            if (miss_subgraph != NULL)
                miss_subgraph->counts[i]++;
#endif
        }
    }
#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
    if ((miss_subgraph != NULL) && ((miss_subgraph->tags->entries & 0xf) == 0))
        report_miss_totals(miss_subgraph->label, (miss_type_count_t*)miss_subgraph);
#endif
    if (is_report_threshold(&miss_type_counts->edge_report_mask, miss_type_counts->counts[edge_miss_index])) {
        report_miss_totals("Totals", miss_type_counts);
    }
}

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
static inline void
merge_left_subgraph_into_right(unrecognized_subgraph_t *left, unrecognized_subgraph_t *right) {
    uint i;
    app_pc tag;

    for (i = 0; i < left->tags->entries; i++) {
        tag = left->tags->array[i];
        unrecognized_subgraph_vector_append(right->tags, tag);
        hashtable_add_replace(unrecognized_subgraphs, tag, right);
    }

    for (i = 0; i < last_miss_type_index; i++)
        right->counts[i] += left->counts[i];

    destroy_unrecognized_subgraph(left);
}
#endif

static void
report_miss_totals(char *label, miss_type_count_t *c) {
    uint anonymous_cross_module_misses = MISS_COUNT(c, white_box_entry_miss) + MISS_COUNT(c, white_box_exit_miss) +
        MISS_COUNT(c, black_box_entry_miss) + MISS_COUNT(c, black_box_exit_miss);
    uint anonymous_intra_misses = MISS_COUNT(c, anonymous_edge_miss) - anonymous_cross_module_misses;
    uint intra_misses = MISS_COUNT(c, edge_miss) - MISS_COUNT(c, cross_module_edge_miss);
    uint image_intra_misses = intra_misses - anonymous_intra_misses;
    uint image_cross_module_misses = MISS_COUNT(c, cross_module_edge_miss) - anonymous_cross_module_misses;

    MON_LOG("%s: N: %d, E: %d, IM: %d (I: %d, A: %d), CM: %d (I: %d, A: %d, WE: %d, WX: %d, BE: %d, BX: %d)\n", label,
        MISS_COUNT(c, node_miss), MISS_COUNT(c, edge_miss), intra_misses, image_intra_misses,
        anonymous_intra_misses, MISS_COUNT(c, cross_module_edge_miss), image_cross_module_misses,
        anonymous_cross_module_misses, MISS_COUNT(c, white_box_entry_miss),
        MISS_COUNT(c, white_box_exit_miss), MISS_COUNT(c, black_box_entry_miss),
        MISS_COUNT(c, black_box_exit_miss));
}

static int
module_id_comparator(module_dataset_t module, char *module_id) {
    return strcmp(MODULE_NAME(module), module_id);
}

static int
relative_tag_comparator(monitor_bb_index_t index, uint relative_tag) {
    return index.relative_tag - relative_tag;
}

#ifdef ANALYZE_UNEXPECTED_SUBGRAPHS
static unrecognized_subgraph_t*
create_unrecognized_subgraph(module_location_t *module) {
    uint i;

    // cs-todo: cleanup
    unrecognized_subgraph_t *subgraph = (unrecognized_subgraph_t *)CS_ALLOC(sizeof(unrecognized_subgraph_t));
    subgraph->tags = (unrecognized_subgraph_vector_t *)CS_ALLOC(sizeof(unrecognized_subgraph_vector_t));
    unrecognized_subgraph_vector_init(subgraph->tags, 8, false, NULL);

    subgraph->id = (ushort)unrecognized_subgraphs->entries;

    subgraph->label = (char *)CS_ALLOC(256);
    dr_snprintf(subgraph->label, 255, "Subgraph #%d in %s", subgraph->id, module->module_name);

    for (i = 0; i < last_miss_type_index; i++)
        subgraph->counts[i] = 0;

    return subgraph;
}

static void
destroy_unrecognized_subgraph(unrecognized_subgraph_t *subgraph) {
    unrecognized_subgraph_vector_delete(subgraph->tags);
    dr_global_free(subgraph->tags, sizeof(unrecognized_subgraph_vector_t));
    dr_global_free(subgraph->label, 256);
    dr_global_free(subgraph, sizeof(unrecognized_subgraph_t));
}
#endif
