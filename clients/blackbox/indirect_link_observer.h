#ifndef INDIRECT_LINK_OBSERVER_H
#define INDIRECT_LINK_OBSERVER_H 1

//#include "../../core/globals.h"
//#include "../../core/x86/arch.h"

#ifdef X64
# define SHADOW_STACK_SENTINEL 0ULL
# define SHADOW_STACK_EMPTY_TAG 0xf0f0f0f0f0f0f0f0ULL
# define SHADOW_STACK_CALLBACK_TAG 0xc0c0c0c0c0c0c0c0ULL
#else
# define SHADOW_STACK_SENTINEL 0UL
# define SHADOW_STACK_EMPTY_TAG 0xf0f0f0f0UL
# define SHADOW_STACK_CALLBACK_TAG 0xc0c0c0c0UL
#endif

// cs-todo: read app max from PE optional header SizeOfStackReserve @72
#define SHADOW_STACK_SIZE 0x1000 // in frames
#define RESOLVED_IMPORT_PEEK(csd) (csd->resolved_imports-1)
#define RESOLVED_IMPORT_POP(csd) (csd->resolved_imports--);

#define SHADOW_FRAME(csd) (csd->shadow_stack-1)
#define SHADOW_PEEK(csd, n) (csd->shadow_stack-(n+1))
#define IS_CALLBACK_FRAME(csd) \
    ((SHADOW_FRAME(csd)->base_pointer == (app_pc)SHADOW_STACK_SENTINEL) && \
    (SHADOW_FRAME(csd)->return_address == (app_pc)SHADOW_STACK_CALLBACK_TAG))
#define GET_SHADOW_STACK_BASE(csd) \
    (((crowd_safe_thread_local_t*)(csd)->crowd_safe_thread_local)->shadow_stack_base)
#define SHADOW_STACK_FRAME_NUMBER(csd, frame) (frame - GET_SHADOW_STACK_BASE(csd))

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
