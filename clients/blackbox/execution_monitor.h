#ifndef EXECUTION_MONITOR_H
#define EXECUTION_MONITOR_H 1

#include "crowd_safe_util.h"
#include "link_observer.h"

// cs-todo: check optimizations on these macro/constant things
#define NOTIFY_UNIT_PREDICATE_EVENT(dcontext, type, predicate) \
do { \
    if (CROWD_SAFE_ALARM()) { \
        increment_predicate(dcontext, offsetof(alarm_data_t, type) + offsetof(unit_predicate_t, predicate)); \
    } \
} while (0)

#define NOTIFY_INTERVAL_PREDICATE_EVENT(dcontext, type, span_index) \
do { \
    if (CROWD_SAFE_ALARM()) { \
        increment_predicate(dcontext, offsetof(alarm_data_t, type) + (span_index * sizeof(uint))); \
    } \
} while (0)

#define NOTIFY_SYSCALL_PREDICATE(dcontext, sysnum) \
do { \
    if (CROWD_SAFE_ALARM()) { \
        increment_predicate(dcontext, offsetof(alarm_data_t, suspicious_syscalls) + (sysnum * sizeof(uint))); \
    } \
} while (0)

typedef struct unit_predicate_t unit_predicate_t;
struct unit_predicate_t {
    uint uib;
    uint suib;
    uint ur;
    uint gencode_write; // no invocations for these last 4 predicates yet (maybe not important)
    uint gencode_perm;
    uint trampoline;
    uint fork;
};

typedef struct interval_span_t interval_span_t;
struct interval_span_t {
    uint micro;
    uint small;
    uint large;
    uint macro;
};

typedef struct alarm_data_t alarm_data_t;
struct alarm_data_t {
    unit_predicate_t instance_predicates;
    unit_predicate_t invocation_predicates;
    interval_span_t uib_intervals;
    interval_span_t suib_intervals;
    //interval_span_t uib_max_consecutive_intervals; // <- cs-todo
    //interval_span_t suib_max_consecutive_intervals;
    uint suspicious_syscalls[0x1a3];
};

/**** image_execution_monitor.c ****/

void
init_execution_monitor();

bool
is_monitor_active();

void
get_monitor_module(module_location_t *module);

void
free_monitor_module(module_location_t *module);

bool
verify_basic_block(dcontext_t *dcontext, module_location_t *module, app_pc tag, bb_state_t *state);

bool
verify_intra_module_edge(dcontext_t *dcontext, module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
    bb_state_t *from_state, bb_state_t *to_state, byte exit_ordinal, graph_edge_type edge_type);

bool
verify_cross_module_edge(dcontext_t *dcontext, module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
    bb_state_t *from_state, bb_state_t *to_state, bb_hash_t edge_hash, graph_edge_type edge_type);

bool
find_unexpected_ibt_precedent(app_pc ibt, module_location_t *ibt_module, bool is_cross_module);

bool
is_abnormal_return(module_location_t *return_bb_module, app_pc return_bb_tag);

// hack:
bool
is_spurious_unexpected_return(module_location_t *return_bb_module, app_pc return_bb_tag);

void
raise_alarm(dcontext_t *dcontext, uint predicate_index, uint counter, uint limit);

void
close_execution_monitor();

/**** anonymous_execution_monitor.c ****/

uint
init_anonymous_execution_monitor(uint anonymous_module_offset);

bool
verify_anonymous_block(module_location_t *module, bb_hash_t bb_hash);

bool
verify_anonymous_edge(dcontext_t *dcontext, module_location_t *module, app_pc from, app_pc to, bb_hash_t to_hash,
    byte exit_ordinal, graph_edge_type edge_type);

bool
verify_anonymous_entry_point(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash, graph_edge_type edge_type);

bool
verify_black_box_export(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t to_hash, bb_hash_t edge_hash);

bool
verify_anonymous_exit_point(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash);

bool
verify_black_box_callout(module_location_t *from_module, module_location_t *to_module,
    app_pc from, app_pc to, bb_hash_t edge_hash);

void
close_anonymous_execution_monitor();

/**** alarm ****/

inline void
increment_predicate(dcontext_t *dcontext, uint predicate_offset) {
    extern alarm_data_t *alarm_counters;
    extern alarm_data_t *alarm_limits;
    uint *counter = (uint *) ((byte *) alarm_counters + predicate_offset);
    uint *limit = (uint *) ((byte *) alarm_limits + predicate_offset);
    uint predicate_index = predicate_offset / sizeof(uint);
    if (++(*counter) >= *limit)
        raise_alarm(dcontext, predicate_index, *counter, *limit);
    else
        CS_DET("MON| tolerating predicate  #%d: %d < %d\n", predicate_index, *counter, *limit);
}

#endif

