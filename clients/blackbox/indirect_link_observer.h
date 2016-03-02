#ifndef INDIRECT_LINK_OBSERVER_H
#define INDIRECT_LINK_OBSERVER_H 1

#include "dr_api.h"
//#include "../../core/globals.h"
//#include "../../core/x86/arch.h"

void
init_indirect_link_observer(dcontext_t *dcontext);

void
indirect_link_observer_thread_init(dcontext_t *dcontext);

/* Inserts an indirect link in the IBP hashtable. Skips the check for existence
 * of the link when `known_new` indicates it could not exist yet. */
void
indirect_link_hashtable_insert(dcontext_t *dcontext);

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
void
harvest_resolved_imports(dcontext_t *dcontext);
#endif

void
push_nested_shadow_stack(dcontext_t *dcontext);

void
pop_nested_shadow_stack(dcontext_t *dcontext);

void
pop_shadow_stack_frame(dcontext_t *dcontext);

void
indirect_link_observer_thread_exit(dcontext_t *dcontext);

void
destroy_indirect_link_observer();

#endif
