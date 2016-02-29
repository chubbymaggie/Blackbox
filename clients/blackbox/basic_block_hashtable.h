#ifndef BASIC_BLOCK_HASHTABLE_H
#define BASIC_BLOCK_HASHTABLE_H 1

#include "crowd_safe_util.h"

/* Instantiate the BB hashtables, which are defined in /ext/drcontainers */
void 
init_bb_hashtable(void);

/* Insert a BB hashcode */
void
insert_bb_hash(app_pc tag, bb_hash_t hash);

bb_state_t *
insert_bb_state(app_pc tag, bb_state_t state);
                
/* Get the hashcode for a BB */
bb_hash_t
get_bb_hash(app_pc tag);

byte
get_tag_version(app_pc tag);

bb_state_t *
get_bb_state(app_pc tag);

void
deactivate_bb(app_pc tag);

void
remove_module_data(app_pc start_pc, app_pc end_pc);

void
deactivate_all();

void
insert_dso_entry(dcontext_t *dcontext, app_pc tag);

/* Track the observation of `sysnum` at `tag`,
 * returning true if it is the first time we have seen `sysnum` at `tag`. */
bool
observe_dynamic_sysnum(dcontext_t *dcontext, app_pc tag, int sysnum);

/* Free a hashcode. */
void 
free_bb_hash(void *hash);

/* Free the 3 hashtables. */
void
destroy_bb_hashtable(void);
#endif
