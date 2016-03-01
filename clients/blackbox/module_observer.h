#ifndef MODULE_OBSERVER_H
#define MODULE_OBSERVER_H 1

/* The Link Observer is responsible for tracking the pairing of basic blocks
 * during execution and generating a hashcode for each such pair. It also
 * gathers diagnostics about the branch instrumentation in DR. This makes it
 * possible to loosely confirm that all known branch instrumentation is
 * accounted for in the CrowdSafe hashlog. At present there is no strict
 * guarantee that all pairings of basic blocks are logged. */

#ifdef UNIX
# include <link.h>
#endif
//#include "../../core/globals.h"
//#include "../../core/fragment.h"
//#include "../../core/module_shared.h"
#include "basic_block_observer.h"
#include "crowd_safe_util.h"

typedef struct function_export_t function_export_t;
struct function_export_t {
    bb_hash_t hash;
    char *function_id;
};

#define HASHTABLE_NAME_KEY export_hashtable
#define HASHTABLE_PAYLOAD_TYPE function_export_t
#include "../drcontainers/drhashtable.h"

void
init_module_observer(bool is_fork);

void
notify_dynamo_initialized();

module_location_t*
get_module_for_address(app_pc instr_start);

short
get_next_relocation(module_location_t *module, app_pc search_start, app_pc search_end);

void
code_area_created(dcontext_t *dcontext, app_pc start, app_pc end);

void
code_area_expanded(app_pc original_start, app_pc original_end, app_pc new_start, app_pc new_end, bool is_dynamo_area);

bool
assign_black_box_singleton(module_location_t *module, bb_hash_t entry_hash);

void
memory_released(dcontext_t *dcontext, app_pc start, app_pc end);

void
add_shadow_pages(dcontext_t *dcontext, app_pc base, size_t size, bool safe_to_read);

void
remove_shadow_pages(dcontext_t *dcontext, app_pc base, size_t size);

bool
observe_shadow_page_entry(module_location_t *from_module, app_pc target_tag);

void
observe_shadow_page_write(dcontext_t *dcontext, module_location_t *writing_module,
                          app_pc writer_tag, app_pc pc, size_t size);

void
write_gencode_edges(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc physical_to, app_pc logical_to,
    bb_state_t *to_state, module_location_t *to_module);

void
add_export_hash(app_pc absolute_address, uint relative_address,
                function_export_t export, bool write_xhash);

bool
register_xhash(char *xhash_name);

#ifdef GENCODE_CHUNK_STUDY
void
notify_shadow_page_decode(app_pc tag);

void
notify_flush(app_pc base, size_t size);
#endif

bool
is_modular_pc(const char *target_module, app_pc target_pc, app_pc lookup_pc);

# ifdef UNIX
/* Scan all loaded modules for PLT entries, adding each to a hashtable
 * for later reference in basic block construction. */
void
register_plt_trampolines(void);
# endif

void
destroy_module_observer();

#endif
