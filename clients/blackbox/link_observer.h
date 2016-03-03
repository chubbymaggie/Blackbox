#ifndef LINK_OBSERVER_H
#define LINK_OBSERVER_H 1

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

/* Initialize the Link Observer module and its descendants, specifically
 * the BB hashtable and CrowdSafe Util. Also called from DR when the current
 * process is forked. No process activity will occur on the forked instance
 * until this function has returned. New log files are created for the child
 * process. */
void
init_link_observer(dcontext_t *dcontext, bool isFork);

/* Called from DR when a new thread is initialized in the target application.
 * Creates a new hashtable to maintain indirect branch history for the thread,
 * and a pair of hashtables to maintain hashcodes for dynamic syscalls. */
void
link_observer_thread_init(dcontext_t *dcontext);

void
crowd_safe_dispatch(dcontext_t *dcontext);

/* Called from DR to notify the Link Observer that the two specified basic blocks
 * are being linked in the code cache. */
void
notify_linking_fragments(dcontext_t *dcontext, app_pc from, app_pc to, byte ordinal);

/* Called from CrowdSafe modules to generate a hashcode for the specified basic blocks.
 * Indirect branch observations must call indirect_link_hashtable_insert, which in turn
 * will call here with any newly observed basic block pairings. */
void
notify_traversing_fragments(dcontext_t *dcontext, app_pc from, app_pc to,
    byte exit_ordinal, graph_edge_type edge_type); //, bool require_to_fragment);

/* Called from DR to notify the Link Observer that the specified basic blocks were
 * just traversed, and that the `to` block includes the last observed dynamic
 * syscall value (found from basic_block_hashtable.c : dsbb_get_dynamic_sysnum()). */
void
notify_traversing_syscall(dcontext_t *dcontext, app_pc dsbb_tag, int syscall_number);

void
code_area_created(dcontext_t *dcontext, app_pc start, app_pc end);

void
code_area_expanded(app_pc original_start, app_pc original_end, app_pc new_start, app_pc new_end, bool is_dynamo_area);

#ifdef UNIX
/* Scan all loaded modules for PLT entries, adding each to a hashtable
 * for later reference in basic block construction. */
void
register_plt_trampolines(void);
#endif

void
notify_process_terminating(bool is_crash);

/* Free memory allocated by the Link Observer module and its submodules. */
void
destroy_link_observer();

/* Called from DR when a thread exits in the target application. Frees the IBP hashtable
 * and syscall hashtables from the dcontext, which holds TLS for that thread. */
void
link_observer_thread_exit(dcontext_t *dcontext);

#endif
