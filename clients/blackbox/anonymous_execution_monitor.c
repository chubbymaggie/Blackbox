#include "execution_monitor.h"
#include "basic_block_hashtable.h"
#include "module_observer.h"

/**** Private Fields ****/

#define MON_WARN(...) CS_WARN("MON| "__VA_ARGS__)
#define MON_LOG(...) CS_DET("MON| "__VA_ARGS__)
#define MON_DET(...) CS_DET("MON| "__VA_ARGS__)

#pragma pack(push, 4)

typedef struct anonymous_bb_t anonymous_bb_t;
struct anonymous_bb_t {
    bb_hash_t hash;
    uint counts; // lo-bit { IM (8) | CS (12) | E (11) | next_hash_same (1) } hi-bit
    uint edges[1]; // fake array size: it's specified in `counts`
};

typedef struct anonymous_bb_index_t anonymous_bb_index_t;
struct anonymous_bb_index_t {
    bb_hash_t hash;
    uint offset;
};

#pragma pack(pop)

  /**** Vector Template · anonymous_bb_index_vector_t ****/

#define VECTOR_NAME_KEY anonymous_bb_index_vector
#define VECTOR_ENTRY_TYPE anonymous_bb_index_t
#define VECTOR_COMPARISON_TYPE bb_hash_t
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvector.h"

#define VECTOR_NAME_KEY anonymous_bb_index_vector
#define VECTOR_ENTRY_TYPE anonymous_bb_index_t
#define VECTOR_COMPARISON_TYPE bb_hash_t
#define VECTOR_SORTED 1
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvectorx.h"

static struct anonymous_dataset_t {
    bool active;
    uint offset;
    // anonymous_black_box_t *black_boxes;
    anonymous_bb_index_vector_t index;
} anonymous_dataset;

typedef struct anonymous_match_t anonymous_match_t;
struct anonymous_match_t {
    app_pc tag;
    anonymous_bb_t *anonymous_bb;
    drvector_t *subgraph;
};

  /**** Vector Template · anonymous_match_vector_t ****/

/*
#define VECTOR_NAME_KEY anonymous_match_vector
#define VECTOR_ENTRY_TYPE anonymous_match_t *
//#define VECTOR_COMPARISON_TYPE app_pc
//#define VECTOR_SORTED 1
//#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvector.h"

#define VECTOR_NAME_KEY anonymous_match_vector
#define VECTOR_ENTRY_TYPE anonymous_match_t *
//#define VECTOR_COMPARISON_TYPE app_pc
//#define VECTOR_SORTED 1
//#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvectorx.h"
*/

  /**** Multimap Template · anonymous_match_multimap_t ****/

#define MULTIMAP_NAME_KEY anonymous_match_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE anonymous_match_t *
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_NAME_KEY anonymous_match_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE anonymous_match_t *
#include "../drcontainers/drmultimapx.h"

// thread-safe under `hashcode_mutex`
static anonymous_match_multimap_t *anonymous_match_multimap;

#define EMPTY_ANONYMOUS_INDEX_MARKER 0xf0f0f0f
#define HAS_NEXT_HASH_BIT 0x80000000U

#define GET_INTRA_MODULE_COUNT(bb) (bb->counts & 0xff)
#define GET_INTRA_MODULE_TO(bb, i) (bb->edges[i] & 0xffffff)
#define GET_INTRA_MODULE_ORDINAL(bb, i) ((bb->edges[i] >> 0x18) & 0xf)
#define GET_INTRA_MODULE_TYPE(bb, i) (bb->edges[i] >> 0x1c)

#define GET_CALLOUT_SITE_COUNT(bb) ((bb->counts >> 0x8) & 0xfff)
#define GET_FIRST_CALLOUT_SITE_HASH(bb) ((bb_hash_t*)(&bb->edges[GET_INTRA_MODULE_COUNT(bb)]))

#define GET_EXPORT_COUNT(bb) ((bb->counts & ~HAS_NEXT_HASH_BIT) >> 0x14)
#define GET_FIRST_EXPORT_HASH(bb) (GET_FIRST_CALLOUT_SITE_HASH(bb) + GET_CALLOUT_SITE_COUNT(bb))

#define GET_BB_DATA_SIZE(bb) (4 /*counts*/ + 8 /*hash*/ + (GET_INTRA_MODULE_COUNT(bb) * 4) + \
    (GET_CALLOUT_SITE_COUNT(bb) * 8) + (GET_EXPORT_COUNT(bb) * 8))

#define GET_BB_INDEX(bb_hash) anonymous_bb_index_vector_search(&anonymous_dataset.index, bb_hash)
#define GET_BB(bb_offset) ((anonymous_bb_t*) int2p(anonymous_dataset.offset + bb_offset))
#define GET_NEXT_BB(bb) ((anonymous_bb_t*) int2p(p2int(bb) + GET_BB_DATA_SIZE(bb)))
#define IS_LAST_BB(bb) (!(bb->counts & HAS_NEXT_HASH_BIT))

/**** Private Prototypes ****/

static int
anonymous_bb_hash_comparator(anonymous_bb_index_t index, bb_hash_t hash);

static inline void
scrub_incompatible_subgraphs(anonymous_match_multimap_entry_t *entry, uint64 compatible_subgraphs);

static inline void
activate_anonymous_bb(app_pc to, anonymous_bb_t *bb, anonymous_match_t *match);

static inline bool
has_match(app_pc tag, anonymous_bb_t *bb);

static void
free_anonymous_match(anonymous_match_t *match);

/**** Public Functions ****/

uint
init_anonymous_execution_monitor(uint anonymous_module_offset) {

    if (anonymous_module_offset == 0) {
        anonymous_dataset.active = false;
        anonymous_dataset.offset = 0;
        return 0;
    }

    anonymous_dataset.active = true;
    anonymous_dataset.offset = p2int(anonymous_module_offset);

    anonymous_dataset.index.array = (anonymous_bb_index_t*)int2p(anonymous_module_offset);
    anonymous_dataset.index.entries = anonymous_dataset.index.array[0].offset / sizeof(anonymous_bb_index_t);
    anonymous_dataset.index.comparator = anonymous_bb_hash_comparator;

    anonymous_match_multimap = (anonymous_match_multimap_t *)CS_ALLOC(sizeof(anonymous_match_multimap_t));
    anonymous_match_multimap_init(anonymous_match_multimap, NULL, "white box subgraph matches");

    if (anonymous_dataset.index.array[0].offset == 0) {
        return (uint)anonymous_dataset.index.array;
    } else if (anonymous_dataset.index.array[0].offset == EMPTY_ANONYMOUS_INDEX_MARKER) {
        anonymous_dataset.index.entries = 0;
        return (uint)anonymous_dataset.index.array + 0xc;
    } else {
        anonymous_bb_index_t *last_index = &anonymous_dataset.index.array[anonymous_dataset.index.entries-1];
        anonymous_bb_t *last_bb = GET_BB(last_index->offset);
        bb_hash_t *first_export;
        bb_hash_t *export_end;

        while (true) {
            first_export = GET_FIRST_EXPORT_HASH(last_bb);
            export_end = first_export + GET_EXPORT_COUNT(last_bb);
            if (IS_LAST_BB(last_bb))
                break;
            else
                last_bb = (anonymous_bb_t *) export_end;
        }

        return p2int(export_end);
    }
}

bool
verify_anonymous_block(module_location_t *module, bb_hash_t bb_hash) {
    anonymous_bb_index_t *index = GET_BB_INDEX(bb_hash);
    if (index == NULL) {
        MON_DET("<miss-anon %s(0x%llx)> Unrecognized bb hash!\n", module->module_name, bb_hash);
        return false;
    }
    return true;
}

bool
verify_anonymous_edge(dcontext_t *dcontext, module_location_t *module, app_pc from, app_pc to, bb_hash_t to_hash,
    byte exit_ordinal, graph_edge_type edge_type)
{
    uint i, j;
    uint64 compatible_subgraphs = 0ULL;
    anonymous_match_multimap_entry_t *entry = anonymous_match_multimap_lookup(anonymous_match_multimap, from);

    if (entry == NULL) {
        MON_DET("<miss-anon %s("PX" -> "PX")> Intra-module 'from' node is not in active anonymous territory.\n",
            module->module_name, from, to);
        return false;
    }

    if (edge_type == call_continuation_edge) {
        // scrub all subgraphs having a different `to` hash for a matching continuation
        for (i = 0; i < anonymous_match_multimap_item_count(entry); i++) {
            anonymous_match_t *match = anonymous_match_multimap_entry_get_item(entry, i);
            anonymous_bb_t *bb = match->anonymous_bb;

            for (j = 0; j < GET_INTRA_MODULE_COUNT(bb); j++) {
                anonymous_bb_t *to_bb = GET_BB(GET_INTRA_MODULE_TO(bb, j));
                if (GET_INTRA_MODULE_TYPE(bb, j) == call_continuation_edge) {
                    if (!has_match(to, to_bb))
                        activate_anonymous_bb(to, to_bb, match);
                    compatible_subgraphs |= (1ULL << i);
                    break;
                }
            }
        }

        if (compatible_subgraphs > 0ULL) {
            MON_DET("<hit-anon %s("PX" -> "PX")> Call continuation.\n", module->module_name, from, to);
            scrub_incompatible_subgraphs(entry, compatible_subgraphs);
            return true;
        } else {
            MON_DET("<miss-anon %s("PX" -> "PX")> No candidates reached this call continuation.\n",
                module->module_name, from, to);
            NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, trampoline);
            return false;
        }
    }

    if (to_hash == 0ULL) {
        MON_WARN("<miss-anon %s("PX" -> "PX")> Hash of the 'to' node is not available.\n",
            module->module_name, from, to);
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, trampoline);
        return false;
    }

    for (i = 0; i < anonymous_match_multimap_item_count(entry); i++) {
        anonymous_match_t *match = anonymous_match_multimap_entry_get_item(entry, i);
        anonymous_bb_t *bb = match->anonymous_bb;

        for (j = 0; j < GET_INTRA_MODULE_COUNT(bb); j++) {
            anonymous_bb_t *to_bb = GET_BB(GET_INTRA_MODULE_TO(bb, j));
            if ((to_bb->hash == to_hash) && (GET_INTRA_MODULE_ORDINAL(bb, j) == exit_ordinal)) {
                if (!has_match(to, to_bb))
                    activate_anonymous_bb(to, to_bb, match);
                compatible_subgraphs |= (1ULL << i);
                break;
            }
        }
    }

    if (compatible_subgraphs > 0ULL) {
        MON_DET("<hit-anon %s("PX" -> "PX")> Intra-module edge.\n", module->module_name, from, to);
        scrub_incompatible_subgraphs(entry, compatible_subgraphs);
        return true;
    } else {
        MON_DET("<miss-anon %s("PX" -> "PX")> No candidates admit this edge.\n",
            module->module_name, from, to);
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, trampoline);
        return false;
    }
}

bool
verify_anonymous_entry_point(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash, graph_edge_type edge_type)
{
    anonymous_bb_index_t *index;
    anonymous_bb_t *bb;
    uint i, edge_count, bb_count = 0;
    bb_hash_t *export_hash;
    bool admitted = false;

    if (to_hash == 0ULL) {
        MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify the edge because the 'to' hash is missing.\n",
            from_module->module_name, from, to_module->module_name, to);
        return false;
    }

    index = GET_BB_INDEX(to_hash);
    if (index == NULL) {
        MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify the edge because the 'to' hash 0x%llx is unrecognized.\n",
            from_module->module_name, from, to_module->module_name, to, to_hash);
        return false;
    }

    // cs-todo: optimization: first check if the entry point is already known
    // if the entry has occurred already, and `from` and `to` have not changed, will it be exactly the same subgraph?
    // yes, if comparing by absolute tag.
    // I can get entries at `to`, but I don't know where they came from.

    bb = GET_BB(index->offset);
    while (true) {
        bb_count++; // debug
        edge_count = GET_EXPORT_COUNT(bb);
        export_hash = GET_FIRST_EXPORT_HASH(bb);
        for (i = 0; i < edge_count; i++, export_hash++) {
            if (*export_hash == edge_hash) {
                if (!has_match(to, bb)) {
                    drvector_t *subgraph = (drvector_t *)CS_ALLOC(sizeof(drvector_t));
                    anonymous_match_t *match = (anonymous_match_t *)CS_ALLOC(sizeof(anonymous_match_t));

                    drvector_init(subgraph, 10, false, NULL);
                    drvector_append(subgraph, match);

                    match->tag = to;
                    match->anonymous_bb = bb;
                    match->subgraph = subgraph;

                    ASSERT(bb->hash == to_hash);

                    anonymous_match_multimap_add(anonymous_match_multimap, to, match);
                }

                admitted = true;
                MON_DET("<hit-anon %s("PX") -> %s("PX")> Export found for 'to' hash 0x%llx.\n",
                    from_module->module_name, from, to_module->module_name, to, to_hash);
            }
        }

        if (IS_LAST_BB(bb))
            break;

        bb = GET_NEXT_BB(bb);
    }

    if (!admitted) {
        MON_DET("<miss-anon %s("PX") -%d-> %s("PX")> Failed to find a matching export of 0x%llx among %d anonymous blocks.\n",
            from_module->module_name, from, edge_type, to_module->module_name, to, edge_hash, bb_count);
    }

    return admitted;
}

bool
verify_black_box_export(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash)
{
    anonymous_bb_index_t *index;
    anonymous_bb_t *bb;
    uint i, edge_count;
    bb_hash_t *export_hash;

    ASSERT(IS_BLACK_BOX(to_module));

    index = GET_BB_INDEX(to_module->black_box_entry); // black box singleton node carries the owner's entry hash
    if (index == NULL) {
        MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify black box callback because "
            "the singleton hash 0x%llx is unrecognized.\n",
            from_module->module_name, from, to_module->module_name, to, to_module->black_box_entry);
        return false;
    }

    bb = GET_BB(index->offset);
    edge_count = GET_EXPORT_COUNT(bb);
    export_hash = GET_FIRST_EXPORT_HASH(bb);
    for (i = 0; i < edge_count; i++, export_hash++) {
        if (*export_hash == edge_hash) {
            MON_DET("<hit-anon %s("PX") -> %s("PX")> Black box callback found.\n",
                from_module->module_name, from, to_module->module_name, to);
            return true; // found a matching callback
        }
    }

    MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify black box callback because "
        "the singleton hash does not admin entry hash 0x%llx.\n",
        from_module->module_name, from, to_module->module_name, to, edge_hash);
    return false;
}

bool
verify_anonymous_exit_point(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash)
{
    uint i, j;
    uint64 compatible_subgraphs = 0ULL;
    anonymous_match_multimap_entry_t *entry;

    entry = anonymous_match_multimap_lookup(anonymous_match_multimap, from);
    if (entry == NULL) {
        MON_DET("<miss-anon %s("PX") -> %s("PX")> Callout site is not in active anonymous territory.\n",
            from_module->module_name, from, to_module->module_name, to);
        return false;
    }

    for (i = 0; i < anonymous_match_multimap_item_count(entry); i++) {
        anonymous_match_t *match = anonymous_match_multimap_entry_get_item(entry, i);
        anonymous_bb_t *bb = match->anonymous_bb;
        bb_hash_t *callout_hash = GET_FIRST_CALLOUT_SITE_HASH(bb);

        for (j = 0; j < GET_CALLOUT_SITE_COUNT(bb); j++, callout_hash++) {
            if (*callout_hash == edge_hash) {
                compatible_subgraphs |= (1ULL << i);
                break;
            }
        }
    }

    if (compatible_subgraphs > 0ULL) {
        MON_DET("<hit-anon %s("PX") -> %s("PX")> Callout found.\n", from_module->module_name, from,
            to_module->module_name, to);
        scrub_incompatible_subgraphs(entry, compatible_subgraphs);
        return true;
    } else {
        uint candidate_count = anonymous_match_multimap_item_count(entry);
        bb_hash_t anonymous_hash = 0ULL;
        if (candidate_count > 0) {
            // bb_hash_t from_hash = get_bb_hash(from);
            anonymous_hash = anonymous_match_multimap_entry_get_item(entry, 0)->anonymous_bb->hash;

            // ASSERT(anonymous_hash == from_hash); // can't: call continuation may admit a wrong node
        }

        MON_DET("<miss-anon %s("PX") -> %s("PX")> All %d candidates at anonymous hash 0x%llx reject callout hash 0x%llx.\n",
            from_module->module_name, from, to_module->module_name, to,
            candidate_count, anonymous_hash, edge_hash);

        return false;
    }
}

bool
verify_black_box_callout(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash)
{
    // black box singleton node carries the owner's entry hash
    anonymous_bb_index_t *index = GET_BB_INDEX(from_module->black_box_entry);

    ASSERT(IS_BLACK_BOX(from_module));

    if (index == NULL) {
        MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify black box callout because "
            "the singleton hash 0x%llx is unrecognized.\n",
            from_module->module_name, from, to_module->module_name, to, from_module->black_box_entry);
        return false;
    } else {
        uint j;
        anonymous_bb_t *bbs = GET_BB(index->offset);
        bb_hash_t *bridge_hash = GET_FIRST_CALLOUT_SITE_HASH(bbs);

        for (j = 0; j < GET_CALLOUT_SITE_COUNT(bbs); j++, bridge_hash++) {
            if (*bridge_hash == edge_hash) {
                MON_DET("<hit-anon %s("PX") -> %s("PX")> Black box callout found.\n",
                    from_module->module_name, from, to_module->module_name, to);
                return true;
            }
        }

        MON_DET("<miss-anon %s("PX") -> %s("PX")> Can't verify black box callout because "
            "the black box does not call out to the target.\n",
            from_module->module_name, from, to_module->module_name, to, edge_hash);
    }

    return false;
}

void
close_anonymous_execution_monitor() {
    if (CROWD_SAFE_MONITOR() && anonymous_dataset.active) {
        anonymous_match_multimap->notify_value_removed = free_anonymous_match;
        anonymous_match_multimap_delete(anonymous_match_multimap);
        dr_global_free(anonymous_match_multimap, sizeof(anonymous_match_multimap_t));
    }
}

/**** Private Functions ****/

static int
anonymous_bb_hash_comparator(anonymous_bb_index_t index, bb_hash_t hash) {
    if (index.hash < hash)
        return -1;
    else if (index.hash > hash)
        return 1;
    else
        return 0;
}

static inline void
scrub_incompatible_subgraphs(anonymous_match_multimap_entry_t *entry, uint64 compatible_subgraphs) {
    int i;
    uint j;
    for (i = (anonymous_match_multimap_item_count(entry)-1); i >= 0; i--) {
        if (!(compatible_subgraphs & (1ULL << i))) {
            anonymous_match_t *match = anonymous_match_multimap_entry_get_item(entry, i);
            drvector_t *subgraph = match->subgraph;
            for (j = 0; j < subgraph->entries; j++) {
                anonymous_match_t *subgraph_match = subgraph->array[j];
                anonymous_match_multimap_remove_value(anonymous_match_multimap, subgraph_match->tag, subgraph_match);
                dr_global_free(subgraph_match, sizeof(anonymous_match_t)); // this will free `match` too
            }
            // cs-todo: can pool the empty subgraphs
            drvector_delete(subgraph);
            dr_global_free(subgraph, sizeof(drvector_t));
        }
    }
}

static inline void
activate_anonymous_bb(app_pc to, anonymous_bb_t *bb, anonymous_match_t *match) {
    anonymous_match_t *to_match = (anonymous_match_t *)CS_ALLOC(sizeof(anonymous_match_t));
    to_match->tag = to;
    to_match->anonymous_bb = bb;
    to_match->subgraph = match->subgraph;
    drvector_append(to_match->subgraph, to_match);
    anonymous_match_multimap_add(anonymous_match_multimap, to, to_match);
}

static inline bool
has_match(app_pc tag, anonymous_bb_t *bb) {
    uint i;
    anonymous_match_multimap_entry_t *entry = anonymous_match_multimap_lookup(anonymous_match_multimap, tag);
    for (i = 0; i < anonymous_match_multimap_item_count(entry); i++) {
        anonymous_match_t *match = anonymous_match_multimap_entry_get_item(entry, i);
        if (match->anonymous_bb == bb)
            return true;
    }
    return false;
}

static void
free_anonymous_match(anonymous_match_t *match) {
    if (match->subgraph->array != NULL) {
        drvector_delete(match->subgraph);
        dr_global_free(match->subgraph, sizeof(drvector_t));
    }
    dr_global_free(match, sizeof(anonymous_match_t));
}
