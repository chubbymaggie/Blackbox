#include "basic_block_hashtable.h"
#include "../../core/x86/instrument.h"
#include "crowd_safe_util.h"

#define HASHTABLE_NAME_KEY bb_hashtable
#define HASHTABLE_PAYLOAD_TYPE bb_state_t
#define HASHTABLE_INIT_EMPTY { 0ULL, 0, false }
#define HASHTABLE_IS_EMPTY(x) x.hash == 0ULL
#include "../drcontainers/drhashtable.h"

#define HASHTABLE_NAME_KEY bb_hashtable
#define HASHTABLE_PAYLOAD_TYPE bb_state_t
#define HASHTABLE_INIT_EMPTY { 0ULL, 0, false }
#define HASHTABLE_IS_EMPTY(x) x.hash == 0ULL
#include "../drcontainers/drhashtablex.h"

/**** private fields ****/

#define BB_KEY_SIZE 13
#define TAG_VERSION_KEY_SIZE 9
#define DSO_KEY_SIZE 9

static bb_hashtable_t *bb_table;
static hashtable_t *dso_table;

typedef struct dynamic_syscall_observation_t dynamic_syscall_observation_t;
struct dynamic_syscall_observation_t {
    uint observed_sysnums[0x200]; // bitmap: one bit per sysnum (max 0x4000)
};

/**** private prototypes ****/

static void
free_dso(void *dso);

static bool
observe_sysnum(dynamic_syscall_observation_t *dso, int sysnum);

/**** public functions ****/

void
init_bb_hashtable() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    bb_table = (bb_hashtable_t*)CS_ALLOC(sizeof(bb_hashtable_t));
    bb_hashtable_init_ex(
        bb_table,
        BB_KEY_SIZE,
        HASH_INTPTR,
        false,
        false,
        NULL,
        NULL, /* no custom hashing */
        NULL);

    dso_table = (hashtable_t*)CS_ALLOC(sizeof(hashtable_t));
    hashtable_init_ex(
        dso_table,
        DSO_KEY_SIZE,
        HASH_INTPTR,
        false,
        false,
        free_dso,
        NULL, /* no custom hashing */
        NULL);

    CS_LOG("\t>> Created BB hashtable at "PX"; table entries at "PX".\n", p2int(bb_table), p2int(bb_table->table));
}

void
insert_bb_hash(app_pc tag, bb_hash_t hash) {
    bb_state_t state;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    assert_hashcode_lock();

    state.hash = hash;
    state.tag_version = 0;
    state.flags = BB_STATE_LIVE;
    bb_hashtable_add_replace(bb_table, tag, state);
}

bb_state_t *
insert_bb_state(app_pc tag, bb_state_t state) {
    bb_state_t *inserted;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, NULL);

    assert_hashcode_lock();

    inserted = bb_hashtable_add_replace(bb_table, tag, state);
    return inserted;
}

bb_hash_t
get_bb_hash(app_pc tag) {
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, NULL);

    assert_hashcode_lock();
    return bb_hashtable_lookup(bb_table, tag)->hash;
}

byte
get_tag_version(app_pc tag) {
    byte version = 0;
    bb_state_t *state;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, NULL);

    assert_hashcode_lock();
    state = bb_hashtable_lookup(bb_table, tag);
    if (state == NULL) {
        CS_ERR("No state for tag version request "PX"\n", tag);
    } else {
        version = state->tag_version;
        DODEBUG({
            if (!IS_BB_LIVE(state))
                CS_DET("State is inactive for tag version request "PX"\n", tag);
        });
    }
    return version;
}

bb_state_t *
get_bb_state(app_pc tag) {
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, NULL);

    assert_hashcode_lock();
    return bb_hashtable_lookup(bb_table, tag);
}

void
deactivate_bb(app_pc tag) {
    bb_state_t *state;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    assert_hashcode_lock();

    CS_DET("Deactivate BB "PX"\n", tag);

    state = bb_hashtable_lookup(bb_table, tag);
    ASSERT(state->hash != 0ULL);
    ASSERT(IS_BB_LIVE(state));

    if (state == NULL) {
        CS_ERR("Failed to locate bb state for tag "PX"\n", tag);
        return;
    }

    if (!IS_BB_LIVE(state))
        CS_WARN("Deactivating an inactive BB "PX"\n", tag);

    DEACTIVATE_BB(state);
    UNSET_BB_UNEXPECTED_RETURN(state);
}

void
remove_module_data(app_pc start_pc, app_pc end_pc) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    CS_DET("Remove module data "PX" - "PX"\n", start_pc, end_pc);

    assert_hashcode_lock();
    bb_hashtable_remove_range(bb_table, start_pc, end_pc);
    hashtable_remove_range(dso_table, start_pc, end_pc);
}

void
deactivate_all() {
    uint i;

    assert_hashcode_lock();

    for (i = 0; i < HASHTABLE_SIZE(bb_table->table_bits); i++) {
        bb_hashtable_entry_t *e = bb_table->table[i];
        while (e != NULL) {
            bb_hashtable_entry_t *nexte = e->next;
            if (!IS_BB_SINGLETON(&(e->payload)))
                DEACTIVATE_BB(&(e->payload));
            e = nexte;
        }
    }
}

void
insert_dso_entry(dcontext_t *dcontext, app_pc tag) {
    dynamic_syscall_observation_t *dso;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    assert_hashcode_lock();

    dso = (dynamic_syscall_observation_t *)CS_ALLOC(sizeof(dynamic_syscall_observation_t));
    memset(dso->observed_sysnums, 0, 0x100 * sizeof(uint));
    hashtable_add(dso_table, tag, dso);
}

bool
observe_dynamic_sysnum(dcontext_t *dcontext, app_pc tag, int sysnum) {
    dynamic_syscall_observation_t *dso;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, false);

    assert_hashcode_lock();

    dso = (dynamic_syscall_observation_t *)hashtable_lookup(dso_table, tag);
    if (dso == NULL)
        return false;

    return observe_sysnum(dso, sysnum);
}

void
free_bb_hash(void *hash) {
    CROWD_SAFE_DEBUG_HOOK_QUIET_VOID(__FUNCTION__);

    dr_global_free(hash, sizeof(bb_hash_t));
}

void
destroy_bb_hashtable() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    CS_LOG("\t>> Destroyed BB hashtable at "PX".\n", p2int(bb_table));

    bb_hashtable_delete(bb_table);
    dr_global_free(bb_table, sizeof(bb_hashtable_t));

    hashtable_delete(dso_table);
    dr_global_free(dso_table, sizeof(hashtable_t));
}

/**** private functions ****/

static void
free_dso(void *dso) {
    dr_global_free(dso, sizeof(dynamic_syscall_observation_t));
}

static inline bool // returns true on first observation
observe_sysnum(dynamic_syscall_observation_t *dso, int sysnum) {
    uint index, mask, bits;

    if (sysnum < 0) {
        CS_ERR("Negative sysnum %d in %s! Ignoring it.\n", sysnum, __FUNCTION__);
        return false;
    }
    if (sysnum >= 0x4000) {
        CS_ERR("Sysnum 0x%x exceeds the limit of the syscall bitmap (0x2000) in %s\n", sysnum, __FUNCTION__);
        return false;
    }

    index = sysnum >> 5;
    bits = dso->observed_sysnums[index];
    mask = 1 << (sysnum & 0xff);
    if ((bits & mask) == 0) {
        dso->observed_sysnums[index] |= mask;
        return true;
    }
    return false;
}
