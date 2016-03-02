#include "indirect_link_hashtable.h"
#include "module_observer.h"
#include "execution_monitor.h"
#include "crowd_safe_trace.h"
#include "crowd_safe_util.h"

/**** hashtablex.h interface elements ****/

static void *tag_xref_mutex;

/**** Multimap Template ****/

// cross-reference table of tag to adjacent bb_tag_pairing_t instances
// entries may be stale, if the other side gets removed

#define MULTIMAP_NAME_KEY xref_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE bb_tag_pairing_t
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimap.h"

#define MULTIMAP_NAME_KEY xref_multimap
#define MULTIMAP_KEY_TYPE app_pc
#define MULTIMAP_VALUE_TYPE bb_tag_pairing_t
#define MULTIMAP_ENTRY_INLINE 1
#include "../drcontainers/drmultimapx.h"

static xref_multimap_t *xref_multimap; // synchronized under TAG_XREF_LOCK

// Locking note: if necessary to hold the xref lock and the table lock at the same time,
// acquire the xref lock first, then the table lock. This occurs in the xref removal callback.
#define TAG_XREF_LOCK dr_mutex_lock(tag_xref_mutex);
#define TAG_XREF_UNLOCK dr_mutex_unlock(tag_xref_mutex);
#define ASSERT_TAG_XREF_LOCK ASSERT(dr_mutex_self_owns(tag_xref_mutex));

#ifdef MONITOR_UNEXPECTED_IBP
typedef struct unexpected_ibp_t unexpected_ibp_t;
struct unexpected_ibp_t {
    app_pc from;
    app_pc to;
    uint edge_index;
    uint flags;
    uint execution_count;
    report_mask_t report_mask;
};

# define UIBP_FROM_EXPECTED 1
# define UIBP_TO_EXPECTED 2
# define UIBP_CROSS_MODULE 4
# define UIBP_ADMITTED 8
# define UIBP_REPORT_PENDING 0x10

# define HASHTABLE_NAME_KEY uibp_hashtable
# define HASHTABLE_KEY_TYPE bb_tag_pairing_t
# include "../drcontainers/drhashtable.h"

# define HASHTABLE_NAME_KEY uibp_hashtable
# define HASHTABLE_KEY_TYPE bb_tag_pairing_t
# include "../drcontainers/drhashtablex.h"

static uibp_hashtable_t *uibp_table;
static bool *final_uibp_report_written;

typedef struct uibp_interval_t uibp_interval_t;
struct uibp_interval_t {
    const uint interval;
    const byte id; // log_10 of `interval`
    const uint index;
    const char *label;
};

static const uibp_interval_t uibp_intervals[UIBP_INTERVAL_COUNT] = {
    { 1000, 3, 0, "micro" },
    { 10000, 4, 1, "short" },
    { 100000, 5, 2, "long" },
    { 1000000, 6, 3, "macro" },
};

typedef struct global_uibp_t global_uibp_t;
struct global_uibp_t {
    uint pending_report_count;
    report_mask_t pending_report_mask;
    clock_type_t last_report;
    uint observed_interval_count[UIBP_INTERVAL_COUNT];
    uint observed_admitted_interval_count[UIBP_INTERVAL_COUNT];
    uint observed_suspicious_interval_count[UIBP_INTERVAL_COUNT];
    uint max_consecutive_intervals[UIBP_INTERVAL_COUNT];
    uint max_consecutive_admitted_intervals[UIBP_INTERVAL_COUNT];
    uint max_consecutive_suspicious_intervals[UIBP_INTERVAL_COUNT];
    report_mask_t report_masks[UIBP_INTERVAL_COUNT];
} *global_uibp;

static drvector_t *pending_uibp_list;

# define MIN_UIBP_REPORT_MASK 0xff
# define MAX_UIBP_REPORT_MASK 0xfffffff

#endif

/**** Private Prototypes ****/

static bb_tag_pairing_t
hash_ibp(app_pc from, app_pc to);

static void
xref_value_removed(bb_tag_pairing_t pairing);

#ifdef MONITOR_UNEXPECTED_IBP
static void
increment_pending_uib_count(dcontext_t *dcontext);

static void
write_uibp_interval_report();

static void
write_pending_uibp_reports(dcontext_t *dcontext);

static void
uibp_removed(void *p);
#endif

static void
hashtable_entry_free_nop(void *);

static void
report_uibp(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, bool is_admitted, app_pc from, app_pc to,
    module_location_t *from_module, module_location_t *to_module, uint edge_index);

/**** Public Functions ****/

void
ibp_hash_global_init(dcontext_t *dcontext) {
    xref_multimap = (xref_multimap_t *)CS_ALLOC(sizeof(xref_multimap_t));
    xref_multimap_init(xref_multimap, xref_value_removed, "ibp xref");

    tag_xref_mutex = dr_mutex_create();
    CS_TRACK(tag_xref_mutex, sizeof(mutex_t));

#ifdef MONITOR_UNEXPECTED_IBP
    {
        uint j;

        uibp_table = (uibp_hashtable_t *)CS_ALLOC(sizeof(uibp_hashtable_t));
        uibp_hashtable_init_ex(
            uibp_table,
            9,
            HASH_INTPTR,
            false,
            false,
            uibp_removed,
            NULL, /* no custom hashing */
            NULL);

        global_uibp = CS_ALLOC(sizeof(global_uibp_t));
        global_uibp->pending_report_count = 0;
        init_report_mask(&global_uibp->pending_report_mask, MIN_UIBP_REPORT_MASK, MAX_UIBP_REPORT_MASK);
        global_uibp->last_report = quick_system_time_millis();
        for (j = 0; j < UIBP_INTERVAL_COUNT; j++) {
            global_uibp->observed_interval_count[j] = 0;
            global_uibp->observed_admitted_interval_count[j] = 0;
            global_uibp->observed_suspicious_interval_count[j] = 0;
            global_uibp->max_consecutive_intervals[j] = 0;
            global_uibp->max_consecutive_admitted_intervals[j] = 0;
            global_uibp->max_consecutive_suspicious_intervals[j] = 0;
            init_report_mask(&global_uibp->report_masks[j], 0xf, 0xffff);
        }

        pending_uibp_list = CS_ALLOC(sizeof(drvector_t));
        drvector_init(pending_uibp_list, 0x40, false, NULL);

        final_uibp_report_written = CS_ALLOC(sizeof(bool));
        *final_uibp_report_written = false;
    }
#endif
}

bb_tag_pairing_t
ibp_hash_lookup(dcontext_t *dcontext, app_pc from, app_pc to) {
    bb_tag_pairing_t key;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, (bb_tag_pairing_t)0x0);

    key = hash_ibp(from, to);
    return dr_ibp_lookup(dcontext, key);
}

bool
ibp_hash_add(dcontext_t *dcontext, app_pc from, app_pc to) {
    bb_tag_pairing_t key;
    bool added = false;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, (bb_tag_pairing_t)0x0);

    // generate the ibp hash id for the from/to pair
    key = hash_ibp(from, to);

    if (dr_ibp_add_new(dcontext, key)) {
        CS_DET("xref (%s): from "PX" to "PX" on thread 0x%x\n", __FUNCTION__, from, to, current_thread_id());

        TAG_XREF_LOCK
        xref_multimap_add(xref_multimap, from, key);
        xref_multimap_add(xref_multimap, to, key);
        TAG_XREF_UNLOCK
        added = true;
    }

    DODEBUG({
        if (!added) {
            if (!ibp_has_incoming_edges(to))
                CS_ERR("IBP table hit on "PX" - "PX" for key 0x%llx, but xref has no incoming edges for 'to'\n", from, to, key);
            ASSERT(ibp_has_incoming_edges(to));
        }
    });

    return added;
}

uint
get_ibp_edge_count(app_pc tag) {
    uint count;
    xref_multimap_entry_t *entry;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, 0U);

    TAG_XREF_LOCK
    entry = xref_multimap_lookup(xref_multimap, tag);
    if (entry == NULL)
        count = 0;
    else
        count = xref_multimap_item_count(entry);
    TAG_XREF_UNLOCK

    return count;
}

bool
ibp_has_incoming_edges(app_pc tag) {
    bool has_edges = false;
    xref_multimap_entry_t *entry;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, 0U);

    TAG_XREF_LOCK
    entry = xref_multimap_lookup(xref_multimap, tag);
    if (entry != NULL) {
        uint i, count = xref_multimap_item_count(entry);
        bb_hash_t key;
        for (i = 0; i < count; i++) {
            key = xref_multimap_entry_get_item(entry, i);
            if ((uint)(key >> 0x20) == p2int(tag)) {
                has_edges = true;
                break;
            }
        }
    }
    TAG_XREF_UNLOCK

    return has_edges;
}

void
ibp_tag_remove(dcontext_t *dcontext, app_pc tag) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    CS_DET("xref (%s): tag "PX"\n", __FUNCTION__, tag);

    TAG_XREF_LOCK
    // calls xref_value_removed() on each removed entry
    xref_multimap_remove_entry(xref_multimap, tag);
    TAG_XREF_UNLOCK
}

void
ibp_clear(dcontext_t *dcontext) {
    dr_ibp_clear(dcontext);

    TAG_XREF_LOCK
    xref_multimap->notify_value_removed = NULL;
    xref_multimap_clear(xref_multimap);
    xref_multimap->notify_value_removed = xref_value_removed;
    TAG_XREF_UNLOCK
}

#ifdef MONITOR_UNEXPECTED_IBP
void
install_unexpected_ibp(dcontext_t *dcontext, app_pc from, app_pc to, module_location_t *from_module,
    module_location_t *to_module, bool is_from_expected, bool is_to_expected, uint edge_index, bool is_admitted, bool is_return)
{
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    uint flags = 0;
    bb_tag_pairing_t key = hash_ibp(from, to); // cs-todo: check for duplicate first?
    unexpected_ibp_t *uibp = (unexpected_ibp_t *)CS_ALLOC(sizeof(unexpected_ibp_t));

    assert_hashcode_lock();

    uibp->from = from;
    uibp->to = to;
    uibp->edge_index = edge_index;

    if (is_from_expected)
        flags |= UIBP_FROM_EXPECTED;
    if (is_to_expected)
        flags |= UIBP_TO_EXPECTED;
    uibp->flags = flags;

    uibp->execution_count = 1;
    uibp->flags |= ((from_module != to_module) * UIBP_CROSS_MODULE);
    uibp->flags |= (is_admitted * UIBP_ADMITTED);
    init_report_mask(&uibp->report_mask, 0xf, 0xffffffff);

    TAG_XREF_LOCK
    if (is_return) {
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, ur);
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, ur);
    } else if (is_admitted) {
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, uib);
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, uib);
    } else {
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, instance_predicates, suib);
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, suib);
    }
    CS_DET("%s| %s("PX") -%c-> %s("PX")\n", is_admitted ? "UIB" : "SUIB",
        from_module->module_name, MODULAR_PC(from_module, from), is_return ? 'R' : '-',
        to_module->module_name, MODULAR_PC(to_module, to));

    {
        unexpected_ibp_t *existing_uibp = uibp_hashtable_lookup(uibp_table, key);
        if (existing_uibp != NULL)
            CS_ERR("Installing over the top of an existing UIBP!\n");
    }

    uibp_hashtable_add(uibp_table, key, uibp);
    xref_multimap_add(xref_multimap, from, key);
    xref_multimap_add(xref_multimap, to, key);
    report_uibp(dcontext, cstl, is_admitted, from, to, from_module, to_module, edge_index);
    increment_pending_uib_count(dcontext);
    TAG_XREF_UNLOCK
}

bool
notify_possibly_unexpected_ibp(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl,
    app_pc from, app_pc to, bool is_unexpected_return)
{
    bb_tag_pairing_t key;
    unexpected_ibp_t *uibp;
    module_location_t *from_module, *to_module;

    if (!CROWD_SAFE_MONITOR())
        return false;

    key = hash_ibp(from, to);

    TAG_XREF_LOCK
    uibp = uibp_hashtable_lookup(uibp_table, key);
    TAG_XREF_UNLOCK

    if (uibp == NULL)
        return false;

    from_module = get_module_for_address(from);
    to_module = get_module_for_address(to);

    TAG_XREF_LOCK
    if (is_unexpected_return)
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, ur);
    else if (uibp->flags & UIBP_ADMITTED)
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, uib);
    else
        NOTIFY_UNIT_PREDICATE_EVENT(dcontext, invocation_predicates, suib);

    CS_DET("%s+| %s("PX") -> %s("PX")\n", (uibp->flags & UIBP_ADMITTED) ? "UIB" : "SUIB",
        from_module->module_name, MODULAR_PC(from_module, from),
        to_module->module_name, MODULAR_PC(to_module, to));

    uibp->execution_count++;
    if ((uibp->flags & UIBP_REPORT_PENDING) == 0) {
        uibp->flags |= UIBP_REPORT_PENDING;
        drvector_append(pending_uibp_list, uibp);
    }

    report_uibp(dcontext, cstl, uibp->flags & UIBP_ADMITTED, from, to, from_module, to_module, uibp->edge_index);
    increment_pending_uib_count(dcontext);
    TAG_XREF_UNLOCK

#ifdef MONITOR_UIBP_ONLINE
    {
        char *label;
        clock_type_t now = quick_system_time_millis();
        bool reported = false;

        cstl->thread_uibp.total++;
        switch (uibp->flags & (UIBP_FROM_EXPECTED | UIBP_TO_EXPECTED)) {
            case 0:
                cstl->thread_uibp.within_unexpected++;
                label = "U->U";
                break;
            case UIBP_FROM_EXPECTED:
                cstl->thread_uibp.from_expected++;
                label = "E->U";
                break;
            case UIBP_TO_EXPECTED:
                cstl->thread_uibp.to_expected++;
                label = "U->E";
                break;
            default:
                cstl->thread_uibp.within_expected++;
                label = "E->E";
        }

        if (is_report_threshold(&uibp->report_mask, uibp->execution_count))
            if (from_module == to_module)
                CS_LOG("UIBP| %d executions of %s ibp %s("PX"->"PX")\n", uibp->execution_count, label,
                    from_module->module_name, MODULAR_PC(from_module, from), MODULAR_PC(to_module, to));
            else
                CS_LOG("UIBP| %d executions of %s ibp %s("PX")->%s("PX")\n",
                    uibp->execution_count, label, from_module->module_name, MODULAR_PC(from_module, from),
                    to_module->module_name, MODULAR_PC(to_module, to));

        if (is_report_threshold(&cstl->thread_uibp.report_mask, cstl->thread_uibp.total))
            CS_LOG("UIBP| %d ibp executions on thread 0x%x: %d E->E, %d U->E, %d E->U, %d U->U\n", cstl->thread_uibp.total,
                current_thread_id(), cstl->thread_uibp.within_expected, cstl->thread_uibp.to_expected,
                cstl->thread_uibp.from_expected, cstl->thread_uibp.within_unexpected);


        if (uibp->flags & UIBP_ADMITTED) {
            from_module->unexpected_ibt.admitted_target_invocations++;
            if ((from_module->unexpected_ibt.last_admitted_target_invocation > 0ULL) &&
                    ((now - from_module->unexpected_ibt.last_admitted_target_invocation) > BUFFER_FLUSH_INTERVAL))
            {
                report_unexpected_ibt(from_module);
                reported = true;
            }

            from_module->unexpected_ibt.last_admitted_target_invocation = now;
            if (from_module->unexpected_ibt.first_admitted_target_invocation == 0ULL) {
                from_module->unexpected_ibt.first_admitted_target_invocation =
                    from_module->unexpected_ibt.last_admitted_target_invocation;
            }
        } else {
            from_module->unexpected_ibt.suspicious_target_invocations++;
            if ((from_module->unexpected_ibt.last_suspicious_target_invocation > 0ULL) &&
                    ((now - from_module->unexpected_ibt.last_suspicious_target_invocation) > BUFFER_FLUSH_INTERVAL))
            {
                report_unexpected_ibt(from_module);
                reported = true;
            }

            from_module->unexpected_ibt.last_suspicious_target_invocation = now;
            if (from_module->unexpected_ibt.first_suspicious_target_invocation == 0ULL) {
                from_module->unexpected_ibt.first_suspicious_target_invocation =
                    from_module->unexpected_ibt.last_suspicious_target_invocation;
            }
        }

        if (!reported)
            report_unexpected_ibt_at_interval(from_module);
    }
#endif

    return true;
}

void
write_stale_uibp_reports(dcontext_t *dcontext, clock_type_t now) { // unsafe reads--slop is ok
    if ((now - global_uibp->last_report) > UIBP_REPORT_INTERVAL) {
        if (global_uibp->pending_report_count > 0) {
            TAG_XREF_LOCK
            output_lock_acquire();
            write_pending_uibp_reports(dcontext);
            write_meta_timepoint();
            init_report_mask(&global_uibp->pending_report_mask, MIN_UIBP_REPORT_MASK, MAX_UIBP_REPORT_MASK);
            output_lock_release();
            TAG_XREF_UNLOCK
        } else if (CROWD_SAFE_META_ON_CLOCK()) { // write meta at ~60 second interval
            output_lock_acquire();
            write_meta_timepoint();
            global_uibp->last_report = now;
            output_lock_release();
        }
    }
}

static void
write_pending_uibp_reports(dcontext_t *dcontext) {
    uint i;
    unexpected_ibp_t *uibp;

    ASSERT_TAG_XREF_LOCK
    assert_output_lock();

    if (global_uibp->pending_report_count == 0)
        return;

    for (i = 0; i < pending_uibp_list->entries; i++) {
        uibp = pending_uibp_list->array[i];
        write_meta_uib(uibp->from, uibp->to, uibp->edge_index, uibp->flags & UIBP_CROSS_MODULE,
            uibp->flags & UIBP_ADMITTED, uibp->execution_count);
        if (CROWD_SAFE_META_ON_CLOCK()) {
            bb_tag_pairing_t key = hash_ibp(uibp->from, uibp->to);

            uibp_hashtable_remove(uibp_table, key);

            dr_ibp_add(dcontext, key);

            xref_multimap_add(xref_multimap, uibp->from, key);
            xref_multimap_add(xref_multimap, uibp->to, key);
        } else {
            uibp->flags &= ~UIBP_REPORT_PENDING;
        }
    }
    drvector_clear(pending_uibp_list);
    global_uibp->pending_report_count = 0;
    global_uibp->last_report = quick_system_time_millis();

    write_uibp_interval_report();
}
#endif

#ifdef MONITOR_UNEXPECTED_IBP
void
write_final_uibp_report() {
    bool repeat;

    if (tag_xref_mutex == NULL)
        return;

    TAG_XREF_LOCK
    repeat = *final_uibp_report_written;
    TAG_XREF_UNLOCK

    if (repeat)
        return;

    CS_LOG("Writing final UIBP report\n");

    TAG_XREF_LOCK
    output_lock_acquire();
    write_uibp_interval_report();
    uibp_hashtable_clear(uibp_table); // prompts an exit report per UIBP
    output_lock_release();
    *final_uibp_report_written = true;
    TAG_XREF_UNLOCK

    finalize_metadata();
}
#endif

void
ibp_hash_global_destroy() {
#ifdef MONITOR_UNEXPECTED_IBP
    hashcode_lock_acquire();
    write_final_uibp_report();
    hashcode_lock_release();
#endif

    TAG_XREF_LOCK
    xref_multimap->notify_value_removed = NULL;
    xref_multimap_delete(xref_multimap);
    dr_global_free(xref_multimap, sizeof(xref_multimap_t));
    TAG_XREF_UNLOCK

    dr_mutex_destroy(tag_xref_mutex);
    tag_xref_mutex = NULL;

#ifdef MONITOR_UNEXPECTED_IBP
	output_lock_acquire();
    uibp_hashtable_delete(uibp_table);
	output_lock_release();
    dr_global_free(uibp_table, sizeof(uibp_hashtable_t));

    dr_global_free(global_uibp, sizeof(global_uibp_t));

    dr_global_free(final_uibp_report_written, sizeof(bool));
#endif
}

/**** Private Functions ****/

// hash is <to, (from <<o 1) ^ to>
static inline bb_tag_pairing_t
hash_ibp(app_pc from, app_pc to) {
#ifdef X64
    ptr_uint_t left, right, rotated_bit;

    left = p2int(to) << 0x20;
    right = p2int(from);
    rotated_bit = ((right & 0x80000000UL) > 0) ? 1 : 0;
    right = ((right << 1) | rotated_bit);
    right = (right ^ p2int(to)) & ALL_LOWER_BITS;
    return (bb_tag_pairing_t)(left | right);
#else
    ptr_uint_t right, rotated_bit;
    bb_tag_pairing_t hash;

    hash = p2int(to);
    hash = hash << 0x20;
    right = p2int(from);
    rotated_bit = ((right & 0x80000000UL) > 0) ? 1 : 0;
    right = ((right << 1) | rotated_bit);
    right = right ^ p2int(to);
    return (bb_tag_pairing_t)(hash | right);
#endif
}

static void
xref_value_removed(bb_tag_pairing_t pairing) {
    bool removed;
    ASSERT_TAG_XREF_LOCK

    removed = dr_ibp_remove(pairing);

#ifdef MONITOR_UNEXPECTED_IBP
    if (removed)
        uibp_hashtable_remove(uibp_table, pairing);
#endif
}

#ifdef MONITOR_UNEXPECTED_IBP
static inline void
increment_pending_uib_count(dcontext_t *dcontext) {
    global_uibp->pending_report_count++;
    if (!CROWD_SAFE_META_ON_CLOCK() &&
        is_report_threshold(&global_uibp->pending_report_mask, global_uibp->pending_report_count)) {
        output_lock_acquire();
        write_pending_uibp_reports(dcontext);
        write_meta_timepoint();
        output_lock_release();
    }
}

static inline void
write_uibp_interval_report() {
    uint i;

    assert_output_lock();

    for (i = 0; i < UIBP_INTERVAL_COUNT; i++) {
        write_meta_uib_interval(uibp_intervals[i].id, 0, global_uibp->observed_interval_count[i],
            (ushort)global_uibp->max_consecutive_intervals[i]);
        write_meta_uib_interval(uibp_intervals[i].id, 1, global_uibp->observed_admitted_interval_count[i],
            (ushort)global_uibp->max_consecutive_admitted_intervals[i]);
        write_meta_uib_interval(uibp_intervals[i].id, 2, global_uibp->observed_suspicious_interval_count[i],
            (ushort)global_uibp->max_consecutive_suspicious_intervals[i]);
    }
}

static void
uibp_removed(void *p) {
    unexpected_ibp_t *uibp = (unexpected_ibp_t*)p;

    assert_output_lock();

    if (*final_uibp_report_written)
        return;

    if (uibp != NULL) {
# ifdef MONITOR_UIBP_ONLINE
        char *label;
        switch (uibp->flags & (UIBP_FROM_EXPECTED | UIBP_TO_EXPECTED)) {
            case 0:
                label = "U->U";
                break;
            case UIBP_FROM_EXPECTED:
                label = "E->U";
                break;
            case UIBP_TO_EXPECTED:
                label = "U->E";
                break;
            default:
                label = "E->E";
        }
        CS_LOG("UIBP| %d executions of %s ibp "PX" -> "PX" (final--removing ibp)\n",
            uibp->execution_count, label, uibp->from, uibp->to);
# endif

        write_meta_uib(uibp->from, uibp->to, uibp->edge_index, uibp->flags & UIBP_CROSS_MODULE,
            uibp->flags & UIBP_ADMITTED, uibp->execution_count);
        dr_global_free(uibp, sizeof(unexpected_ibp_t));
    }
}
#endif

#ifdef MONITOR_UNEXPECTED_IBP
static void
report_uibp(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, bool is_admitted,
            app_pc from, app_pc to,
            module_location_t *from_module, module_location_t *to_module, uint edge_index)
{
    uint i;
    local_security_audit_state_t *csd = GET_CS_DATA(dcontext);
    clock_type_t interval, uibp_interval, suibp_interval;
    app_pc xsp = dcontext_get_app_stack_pointer(dcontext);

    ASSERT_TAG_XREF_LOCK

    if (csd->stack_spy_mark == 0UL) {
        CS_DET("SPY| Activating stack suspicion for %s("PX") -> %s("PX") at XSP="PX"\n",
               from_module->module_name, MODULAR_PC(from_module, from),
               to_module->module_name, MODULAR_PC(to_module, to), xsp);
        csd->stack_spy_mark = p2int(xsp);
        cstl->stack_suspicion.uib_count = (is_admitted > 0);
        cstl->stack_suspicion.suib_count = !is_admitted;
        if (from_module == to_module) {
            cstl->stack_suspicion.raising_edge_is_cross_module = false;
            cstl->stack_suspicion.raising_edge_index = edge_index;
        } else {
            cstl->stack_suspicion.raising_edge_is_cross_module = true;
            cstl->stack_suspicion.raising_edge_index = edge_index;
        }
    } else {
        if (is_admitted) {
            if (cstl->stack_suspicion.uib_count < 0xffff)
                cstl->stack_suspicion.uib_count++;
        } else {
            if (cstl->stack_suspicion.suib_count < 0xffff)
                cstl->stack_suspicion.suib_count++;
        }
    }

    uibp_interval = (cstl->thread_clock.clock - cstl->thread_clock.last_uibp_timestamp);
    suibp_interval = (cstl->thread_clock.clock - cstl->thread_clock.last_suibp_timestamp);
    if (uibp_interval < suibp_interval)
        interval = uibp_interval;
    else
        interval = suibp_interval;

    for (i = 0; i < UIBP_INTERVAL_COUNT; i++) {
        if (interval < uibp_intervals[i].interval) {
            if (global_uibp->observed_interval_count[i] < 0xffffffffUL) {
                global_uibp->observed_interval_count[i]++; // cs-todo: duplicate counters for intervals
                NOTIFY_INTERVAL_PREDICATE_EVENT(dcontext, uib_intervals, i);
# ifdef MONITOR_UIBP_ONLINE
                if (is_report_threshold(&global_uibp->report_masks[i], global_uibp->observed_interval_count[i]))
                    CS_LOG("UIBP| %d %s intervals (%d cycles each)\n",
                        global_uibp->observed_interval_count[i], uibp_intervals[i].label, uibp_intervals[i].interval);
# endif
                if (cstl->thread_clock.consecutive_interval_count[i] < 0xffffffffUL) {
                    cstl->thread_clock.consecutive_interval_count[i]++;
                    if (cstl->thread_clock.consecutive_interval_count[i] > global_uibp->max_consecutive_intervals[i]) {
                        global_uibp->max_consecutive_intervals[i] = cstl->thread_clock.consecutive_interval_count[i];
# ifdef MONITOR_UIBP_ONLINE
                        CS_LOG("UIBP| %d consecutive %s intervals (%d cycles each)\n",
                            cstl->thread_clock.consecutive_interval_count[i],
                                uibp_intervals[i].label, uibp_intervals[i].interval);
# endif
                    }
                }
            }
        } else {
            cstl->thread_clock.consecutive_interval_count[i] = 0;
        }

        if (is_admitted) {
            if (uibp_interval < uibp_intervals[i].interval) {
                if (global_uibp->observed_admitted_interval_count[i] < 0xffffffffUL) {
                    global_uibp->observed_admitted_interval_count[i]++;
                    if (cstl->thread_clock.last_uibp_is_admitted) {
                        if (cstl->thread_clock.consecutive_admitted_interval_count[i] < 0xffffffffUL) {
                            cstl->thread_clock.consecutive_admitted_interval_count[i]++;
                            if (cstl->thread_clock.consecutive_admitted_interval_count[i] >
                                    global_uibp->max_consecutive_admitted_intervals[i])
                                global_uibp->max_consecutive_admitted_intervals[i] =
                                    cstl->thread_clock.consecutive_admitted_interval_count[i];
                        }
                    } else {
                        cstl->thread_clock.consecutive_admitted_interval_count[i] = 0;
                    }
                }
            } else {
                cstl->thread_clock.consecutive_admitted_interval_count[i] = 0;
            }
        }

        if (!is_admitted) {
            if (suibp_interval < uibp_intervals[i].interval) {
                if (global_uibp->observed_suspicious_interval_count[i] < 0xffffffffUL) {
                    global_uibp->observed_suspicious_interval_count[i]++;
                    NOTIFY_INTERVAL_PREDICATE_EVENT(dcontext, suib_intervals, i);
                    if (!cstl->thread_clock.last_uibp_is_admitted) {
                        if (cstl->thread_clock.consecutive_suspicious_interval_count[i] < 0xffffffffUL) {
                            cstl->thread_clock.consecutive_suspicious_interval_count[i]++;
                            if (cstl->thread_clock.consecutive_suspicious_interval_count[i] >
                                    global_uibp->max_consecutive_suspicious_intervals[i])
                                global_uibp->max_consecutive_suspicious_intervals[i] =
                                    cstl->thread_clock.consecutive_suspicious_interval_count[i];
                        }
                    } else {
                        cstl->thread_clock.consecutive_suspicious_interval_count[i] = 0;
                    }
                }
            } else {
                cstl->thread_clock.consecutive_suspicious_interval_count[i] = 0;
            }
        }
    }

# ifdef MONITOR_UIBP_ONLINE
    if (interval < uibp_intervals[0].interval) {
        if (from_module == to_module)
            CS_LOG("UIBP| micro interval %d: %s("PX" -> "PX") %s -> %s, %d consecutive\n", (uint)interval,
                from_module->module_name, MODULAR_PC(from_module, from), MODULAR_PC(to_module, to),
                cstl->thread_clock.last_uibp_is_admitted ? "Adm" : "Susp", is_admitted ? "Adm" : "Susp",
                cstl->thread_clock.consecutive_interval_count[0]);
        else
            CS_LOG("UIBP| micro interval %d: %s("PX") -> %s("PX") %s -> %s, %d consecutive\n", (uint)interval,
                from_module->module_name, MODULAR_PC(from_module, from), to_module->module_name, MODULAR_PC(to_module, to),
                cstl->thread_clock.last_uibp_is_admitted ? "Adm" : "Susp", is_admitted ? "Adm" : "Susp",
                cstl->thread_clock.consecutive_interval_count[0]);
    }
# endif

    if (!is_admitted)
        cstl->thread_clock.last_suibp_timestamp = cstl->thread_clock.clock;
    cstl->thread_clock.last_uibp_timestamp = cstl->thread_clock.clock;
    cstl->thread_clock.last_uibp_is_admitted = is_admitted;
}
#endif
