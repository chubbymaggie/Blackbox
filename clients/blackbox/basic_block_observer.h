#ifndef BASIC_BLOCK_OBSERVER_H
#define BASIC_BLOCK_OBSERVER_H 1

/* The BB observer is responsible for maintaining the hashtable of basic
 * blocks, and for directing the observation of dynamic syscalls. */

#include "dr_api.h"

//#include "../../core/globals.h"
//#include "../../core/instrlist.h"

void
init_basic_block_observer(bool isFork);

void
write_graph_metadata();

/* Called from DR during construction of a basic block, before the majority of
 * DR instrumentation is applied to `ilist`. A hashcode is generated for the BB
 * and placed in the BB hashtable (basic_block_hashtable). If the BB contains a
 * static syscall, the syscall number is explicitly added to the hashcode. If the
 * BB contains a dynamic syscall, the BB tag is inserted into the DSBB hashtable
 * for future reference. If the BB is the `to` block of an IBL lookup (as noted
 * in the ibp_table of arch_exports.h), then emit the corresponding pair hash
 * to the hashlog and add it to the IBP table. If the user has requested a BB
 * analysis file, the requested content is output to the analysis file. */
void
notify_basic_block_constructed(dcontext_t *dcontext,
    app_pc tag, instrlist_t *ilist, int syscall_number);

void
notify_trace_constructed(dcontext_t *dcontext, instrlist_t *ilist);

uint
instrument_return_site(dcontext_t *dcontext, instrlist_t *ilist, instr_t *next, app_pc tag);

void
notify_basic_block_removed(dcontext_t *dcontext, app_pc tag);

void
notify_cache_reset();

void
crowd_safe_thread_reset(dcontext_t *dcontext);

#ifdef DEBUG
void
ibp_testify(app_pc tag);
#endif

void
close_basic_block_observer();

#endif
