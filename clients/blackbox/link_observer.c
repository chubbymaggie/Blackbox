#include "link_observer.h"
#include <string.h>
#include "crowd_safe_util.h"
#include "module_observer.h"
#include "crowd_safe_trace.h"
#include "basic_block_observer.h"
#include "basic_block_hashtable.h"
#include "indirect_link_observer.h"
#include "indirect_link_hashtable.h"
#include "network_monitor.h"
#include "crowd_safe_gencode.h"
#include "execution_monitor.h"
#include "blacklist.h"

#ifdef WINDOWS
# include "winbase.h"
#endif

#ifdef UNIX
# include "../../core/unix/module.h"
# include <sys/types.h>
# include <sys/syscall.h>
#endif

/**** Private Fields ****/

static int *initialized_thread_count;
static uint *debug_count;

typedef struct _suspended_shadow_stack_t {
    shadow_stack_frame_t *shadow_stack_base;
    shadow_stack_frame_t *current_frame;
} suspended_shadow_stack_t;

#define SUSPENDED_SHADOW_STACKS_KEY_SIZE 5

static hashtable_t *suspended_shadow_stacks;

/**** Private Prototypes ****/

static void
flush_output_buffers();

static void
process_exit(void);

/**** Public Functions ****/

void
init_link_observer(dcontext_t *dcontext, bool is_fork) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    init_crowd_safe_util(is_fork);

    if (is_fork) {
        *initialized_thread_count = 1;
    } else {
        init_bb_hashtable();
        ibp_hash_global_init(dcontext);
        initialized_thread_count = (int*)CS_ALLOC(sizeof(int));
        *initialized_thread_count = 0;

        suspended_shadow_stacks = (hashtable_t*)CS_ALLOC(sizeof(hashtable_t));
        hashtable_init_ex(
            suspended_shadow_stacks,
            SUSPENDED_SHADOW_STACKS_KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            NULL,
            NULL, /* no custom hashing */
            NULL);
    }

    init_crowd_safe_trace(is_fork);
    // init_module_observer(is_fork);

    if (CROWD_SAFE_NETWORK_MONITOR())
        init_network_monitor();

    init_blacklist();
    init_basic_block_observer(is_fork);
    init_indirect_link_observer(dcontext);
    init_crowd_safe_gencode();
    write_graph_metadata();

    dr_register_exit_event(process_exit);

    debug_count = CS_ALLOC(sizeof(uint));
    *debug_count = 0;
}

void
link_observer_thread_init(dcontext_t *dcontext) {
    uint i;
    crowd_safe_thread_local_t *cstl;
    clock_type_t now = quick_system_time_millis();
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    (*initialized_thread_count)++;
    CS_DET("Call #%d to %s:%s for dcontext "PX" on thread %d\n",
           *initialized_thread_count, __FILE__, __FUNCTION__,
           p2int(dcontext), current_thread_id());

    cstl = (crowd_safe_thread_local_t *)CS_ALLOC(sizeof(crowd_safe_thread_local_t));
#ifdef MONITOR_ENTRY_RATE
    cstl->thread_init_tsc = now;
    cstl->dr_entry_count = 0;
#endif
    cstl->bb_meta.state = NULL;
    cstl->bb_meta.syscall_number = -1;
    cstl->bb_meta.clobbered_black_box_hash = 0ULL;
    cstl->bb_meta.is_black_box_thrash = false;
#ifdef DEBUG
    cstl->bb_meta.created_ibp_edge = false;
#endif
#ifdef MONITOR_UIBP_ONLINE
    cstl->thread_uibp.total = 0;
    cstl->thread_uibp.within_expected = 0;
    cstl->thread_uibp.within_unexpected = 0;
    cstl->thread_uibp.from_expected = 0;
    cstl->thread_uibp.to_expected = 0;
    init_report_mask(&cstl->thread_uibp.report_mask, 0xfff, 0xffffffff);
#endif
#ifdef MONITOR_UNEXPECTED_IBP
    cstl->thread_clock.last_fcache_entry = 0ULL;
    cstl->thread_clock.clock = 0ULL;
    cstl->thread_clock.is_in_app_fcache = false;
    cstl->thread_clock.last_uibp_timestamp = now;
    cstl->thread_clock.last_suibp_timestamp = now;
    cstl->thread_clock.last_uibp_is_admitted = false;
    for (i = 0; i < UIBP_INTERVAL_COUNT; i++) {
        cstl->thread_clock.consecutive_interval_count[i] = 0;
        cstl->thread_clock.consecutive_admitted_interval_count[i] = 0;
        cstl->thread_clock.consecutive_suspicious_interval_count[i] = 0;
    }
    cstl->stack_suspicion.uib_count = 0;
    cstl->stack_suspicion.suib_count = 0;
#endif
    cstl->stack_walk = CS_ALLOC(sizeof(return_address_iterator_t));
    CS_TRACK(cstl->stack_walk, sizeof(return_address_iterator_t));

    SET_CSTL(dcontext, cstl);

    indirect_link_observer_thread_init(dcontext);
}

void
crowd_safe_dispatch(dcontext_t *dcontext) {
    local_security_audit_state_t *csd;
    ibp_metadata_t *ibp_data;

#ifdef MONITOR_ENTRY_RATE
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    if ((++cstl->dr_entry_count & 0xffff) == 0) {
        clock_type_t cycles = quick_system_time_millis() - cstl->thread_init_tsc;
        CS_LOG("DR entry rate on thread 0x%x: %d cycles (clock 0x%x)\n", current_thread_id(),
               (uint)(cycles / cstl->dr_entry_count), quick_system_time_millis());
    }
#endif

    crowd_safe_heartbeat(dcontext);

#ifdef MONITOR_UNEXPECTED_IBP
    stop_fcache_clock(dcontext);
#endif
#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
    harvest_resolved_imports(dcontext);
#endif

    DODEBUG(GET_CSTL(dcontext)->bb_meta.created_ibp_edge = false;);

    csd = GET_CS_DATA(dcontext);
    ibp_data = &csd->ibp_data;

    if (ibp_data->ibp_from_tag == PC(0)) {
        IBP_SET_META(ibp_data, &, ~IBP_META_PATH_PENDING); // bogus ibp
        //ibp_data->ibp_from_tag = (app_pc)PC(1); // for debugging, to know which pass actually set a 0
    }
    if (!IBP_PATH_IS_PENDING(ibp_data)) {
        ibp_data->ibp_from_tag = PC(0); // prevent syscall IBL from thinking it's IBP
    }

    // dr_analyze_shadow_stack(dcontext, csd, "#disp#");

    if (IBP_IS_NEW_PATH(ibp_data)) {   // found a new IBP

#ifdef SEED_TLS_FOR_IBL_VERIFICATION
        ASSERT(ibp_data->ibp_from_tag == int2p(0x12345678));
#endif

        IBP_SET_META(ibp_data, &, ~IBP_META_NEW_PATH); // ack the new IBP

        /*
        if (ibp_data->ibp_to_tag == NULL) { // app is doing something bogus
            CS_LOG("Bogus indirect branch from "PX" to 0x0!\n", ibp_data->ibp_from_tag);
            fcache_enter = get_fcache_enter_shared_routine(dcontext);
            set_fcache_target(dcontext, 0);
            dcontext->whereami = WHERE_FCACHE;
#ifdef MONITOR_UNEXPECTED_IBP
            start_fcache_clock(dcontext, false);
#endif
            (*fcache_enter)(dcontext);
            ASSERT_NOT_REACHED();
        }
        */

        // dr_printf("Dispatch from fcache for IBP from 0x%lx to 0x%lx\n",
        // ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);

        ASSERT(IBP_PATH_IS_PENDING(ibp_data));
        ASSERT(!IBP_STACK_IS_PENDING(ibp_data));
        // expected returns must be filtered out in the IBL routine
        ASSERT(!(IBP_IS_RETURN(ibp_data) && !IBP_IS_UNEXPECTED_RETURN(ibp_data)));

        indirect_link_hashtable_insert(dcontext);

#ifdef MONITOR_UNEXPECTED_IBP
        start_fcache_clock(dcontext, false);
#endif
        dr_enter_fcache(dcontext, ibp_data->ibp_to_tag);
        ASSERT_NOT_REACHED(); // app will not know this "call" happened, so never returns here
    } else {
        if (IBP_STACK_IS_PENDING(ibp_data)) {
            shadow_stack_frame_t *top = SHADOW_FRAME(csd);
            app_pc to_tag = ibp_data->ibp_to_tag;
            bool matched_address = false;
            bool context_switch = false;
            uint unwind_count = 0;
            app_pc xsp = dcontext_get_app_stack_pointer(dcontext);

#ifdef MONITOR_UNEXPECTED_IBP
            if (p2int(xsp) < csd->stack_spy_mark) {
                CS_DET("SPY| Clearing stack suspicion at XSP="PX"\n", xsp);
                csd->stack_spy_mark = 0UL;
            }
#endif

            if (to_tag != dcontext_get_next_tag(dcontext)) {
                CS_DET("ibp_to_tag ("PX") differs from dcontext->next_tag ("PX")\n",
                    to_tag, dcontext->next_tag);
            }

            ASSERT(IBP_IS_RETURN(ibp_data));
            check_shadow_stack_bounds(csd);
            if ((p2int(top->base_pointer) != SHADOW_STACK_SENTINEL) &&
                    (to_tag != top->return_address)) {
                to_tag = dcontext_get_next_tag(dcontext);
            }
            if ((p2int(top->base_pointer) != SHADOW_STACK_SENTINEL) &&
                    (to_tag == top->return_address)) {
#ifdef X64
                ASSERT(SHADOW_FRAME(csd)->base_pointer <= xsp);
                ASSERT((SHADOW_FRAME(csd)->base_pointer == (app_pc)SHADOW_STACK_SENTINEL) ||
                        SHADOW_FRAME(csd)->base_pointer == xsp);
#endif
                csd->shadow_stack--;
                matched_address = true;
            } else {
                bool expected = false;
                int stack_delta = xsp - top->base_pointer;
                if (stack_delta < 0)
                    stack_delta = -stack_delta;

                csd->shadow_stack_miss_frame = csd->shadow_stack;
                if (xsp <= GET_SHADOW_STACK_BOTTOM_FRAME(csd) && (xsp + 0x20) >= top->base_pointer) { // stack_delta > 0x1000) {
                    while ((SHADOW_FRAME(csd)->base_pointer < xsp) &&
                           (SHADOW_FRAME(csd)->base_pointer != (app_pc)SHADOW_STACK_SENTINEL))
                    {
                        csd->shadow_stack--;
                        unwind_count++;
                        if (ibp_data->ibp_to_tag == SHADOW_FRAME(csd)->return_address) {
                            expected = true;
                            matched_address = true;
                            break;
                        }
                    }
                } else {
                    context_switch = true;
                }
                if (!expected)
                    IBP_SET_META(ibp_data, |, IBP_META_UNEXPECTED_RETURN);
            }
            IBP_SET_META(ibp_data, &, ~IBP_META_STACK_PENDING);

#ifdef DEBUG
            if (xsp != top->base_pointer) {
                uint i;
                local_security_audit_state_t *csd = GET_CS_DATA(dcontext);
                shadow_stack_frame_t *entry;
                for (i = 5; i > 0; i--) {
                    entry = SHADOW_FRAME(csd) - i;
                    if (entry <= GET_SHADOW_STACK_BASE(csd))
                        break;
                    if (entry->base_pointer == int2p(SHADOW_STACK_SENTINEL))
                        break;
                    if ((entry-1)->base_pointer != int2p(SHADOW_STACK_SENTINEL) &&
                            entry->base_pointer > (entry-1)->base_pointer) {
                        CS_DET("Shadow frame "PX" ("PX") drops below parent frame "PX" ("PX")\n",
                            entry->base_pointer, entry->return_address,
                            (entry-1)->base_pointer, (entry-1)->return_address);
                    }
                    if (xsp > entry->base_pointer) {
                        CS_DET("XSP "PX" > frame(%d) "PX" by %d words | last_fragment "PX" | next tag "PX"\n",
                            xsp, i, entry->base_pointer,
                            (p2int(xsp) - p2int(entry->base_pointer)) / 4,
                            dcontext->last_fragment->tag, dcontext->next_tag);
                        break;
                    }
                }
            }
#endif

            if (p2int(top->base_pointer) == SHADOW_STACK_SENTINEL) {
                CS_ERR("<ss> during IBP return, shadow stack "PX"(%d) points at a sentinel"
                       "on thread 0x%x\n", p2int(top), SHADOW_STACK_FRAME_NUMBER(csd, top),
                       current_thread_id());
            } else if (matched_address) {
                if (unwind_count > 1) {
                    CS_DET("<ss> TC: %d unwound to frame %d\n", unwind_count,
                           SHADOW_STACK_FRAME_NUMBER(csd, top));
                }
            } else if (context_switch) {
                crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
                suspended_shadow_stack_t *sss;

                // how to clean up stale ones?
                // maybe push this into indirect_link_obs?

                CS_LOG("<ss> context switch at frame %d on thread 0x%x\n",
                       SHADOW_STACK_FRAME_NUMBER(csd, top), current_thread_id());

                sss = (suspended_shadow_stack_t *) hashtable_lookup(suspended_shadow_stacks, to_tag);
                if (sss == NULL) {
                    // maybe scan for an sss having active base pointer near XSP?

                    sss = CS_ALLOC(sizeof(suspended_shadow_stack_t));
                    sss->shadow_stack_base = cstl->shadow_stack_base;
                    sss->current_frame = SHADOW_FRAME(csd);
                    install_new_shadow_stack(dcontext);
                } else {
                    suspended_shadow_stack_t sss_temp;

                    sss_temp.shadow_stack_base = cstl->shadow_stack_base;
                    sss_temp.current_frame = SHADOW_FRAME(csd);

                    cstl->shadow_stack_base = sss->shadow_stack_base;
                    csd->shadow_stack = sss->current_frame;

                    hashtable_remove(suspended_shadow_stacks, to_tag);
                    *sss = sss_temp; /* fieldwise copy */

                    // dr_global_free(sss, sizeof(suspended_shadow_stack_t)); // when is it obsolete?
                }
                hashtable_add(suspended_shadow_stacks, sss->current_frame->return_address, sss);
            } else {
                CS_DET("<ss> UR (%d unwound) XSP: "PX" %s SS.XSP: "PX" @ "PX"(%d)"
                       " | ibp_to: "PX" %s SS.addr: "PX"; thread 0x%x\n",
                       unwind_count, xsp, xsp > top->base_pointer ? ">" : "<",
                       top->base_pointer, int2p(top), SHADOW_STACK_FRAME_NUMBER(csd, top),
                       ibp_data->ibp_to_tag, ibp_data->ibp_to_tag == top->return_address ? "==" : "!=",
                       top->return_address, current_thread_id());
            }
        } else {
            CS_DET("<ss-match>\n");
        }
    }
}

void
notify_linking_fragments(dcontext_t *dcontext, app_pc from, app_pc to, byte exit_ordinal)
{
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    notify_traversing_fragments(dcontext, from, to, exit_ordinal, direct_edge); //, false))
}

// it's very important for ibp hashes to not call this function directly.
// ibp hashes must call indirect_link_hashtable_insert().
void
notify_traversing_fragments(dcontext_t *dcontext, app_pc from, app_pc to,
    byte exit_ordinal, graph_edge_type edge_type)
{
    bb_state_t *from_state, *to_state;
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    module_location_t *from_module = get_module_for_address(from);
    module_location_t *to_module = get_module_for_address(to);
#ifdef UNIX
    trampoline_tracker *trampoline;
#endif
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    ASSERT((from == to) || !IS_BUILDING_TAG(cstl, to));

    hashcode_lock_acquire();

    if (edge_type == unexpected_return_edge) {
        if (from_module->type != module_type_anonymous && to_module->type != module_type_anonymous) {
            CS_DET("%s("PFX") -UR-> %s("PFX") on thread 0x%x\n", from_module->module_name,
                   MODULAR_PC(from_module, from), to_module->module_name,
                   MODULAR_PC(to_module, to), current_thread_id());
        } else {
            CS_DET("%s("PFX") -UR-> %s("PFX") on thread 0x%x\n", from_module->module_name,
                   MODULAR_PC(from_module, from), to_module->module_name,
                   MODULAR_PC(to_module, to), current_thread_id());
        }
    } else {
        CS_DET("%s("PFX") -%d-> %s("PFX") on thread 0x%x\n", from_module->module_name,
               MODULAR_PC(from_module, from), edge_type, to_module->module_name,
               MODULAR_PC(to_module, to), current_thread_id());
    }

    from_state = get_bb_state(from);
    ASSERT(from_state != NULL);
    DODEBUG({
        if (!IS_BB_LIVE(from_state))
            CS_WARN("Creating edge to "PX" from inactive BB "PX"\n", to, from);
    });

    to_state = get_bb_state(to);

    if (to_state == NULL || !IS_BB_LIVE(to_state)) {
        if (!(IS_BLACK_BOX(from_module) && IS_BLACK_BOX(to_module)))
            add_pending_edge(from, to, exit_ordinal, edge_type, from_module, to_module, true);
        hashcode_lock_release();
        return;
    }

    hashcode_lock_release();

#ifdef UNIX
    if (omit_bb_from_static_hash_output(from) || omit_bb_from_static_hash_output(to))
        return;

    // cs-todo: filter out edges from PLT to function entries
    trampoline = hashtable_lookup(trampoline_trackers, to);
    if (trampoline != NULL) { // `to` is a trampoline--process the tracker and return early
        hashcode_lock_acquire();
        resolve_pending_trampolines();
        if (trampoline->function_entry == NULL) { // not resolved
            pend_trampoline_caller(trampoline, from, exit_ordinal, edge_type == direct_edge);
        } else { // resolved: write call edge
            ASSERT(trampoline->function_callers == NULL);
            write_trampoline(trampoline, from, exit_ordinal, edge_type);
        }
        hashcode_lock_release();
        return true; // an edge will be written, so respond like it has been done
    }
    // filter out the jump from the trampoline to its expected destination
    if (edge_type == indirect_edge) {
        trampoline = hashtable_lookup(trampoline_trackers, from);
        if ((trampoline != NULL) && (trampoline->function_entry != NULL)) {
            ASSERT(trampoline->function_entry == to);
            return true; // acknowledge the edge, even though it will not be written
        }
    }
#endif

    hashcode_lock_acquire();
    write_link(dcontext, from, to, from_state, to_state, from_module, to_module, exit_ordinal, edge_type);
    hashcode_lock_release();
}

void
notify_traversing_syscall(dcontext_t *dcontext, app_pc dsbb_tag, int syscall_number) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    /*
    if (syscall_number > 0x1a3) {
        module_location_t *dsbb_module = get_module_for_address(dsbb_tag);
        CS_LOG("SYS| syscall 0x%x from %s("PX")\n", syscall_number, dsbb_module->module_name, MODULAR_PC(dsbb_module, dsbb_tag));
    }
    */

    hashcode_lock_acquire();
    if (observe_dynamic_sysnum(dcontext, dsbb_tag, syscall_number)) {
        module_location_t *dsbb_module = get_module_for_address(dsbb_tag);
        app_pc syscall_singleton_pc = (SYSCALL_SINGLETON_START + syscall_number);

        CS_DET("Dynamic syscall %d from %s("PX")\n", syscall_number, dsbb_module->module_name, MODULAR_PC(dsbb_module, dsbb_tag));

        write_link(dcontext, dsbb_tag, syscall_singleton_pc, get_bb_state(dsbb_tag),
            get_bb_state(syscall_singleton_pc), dsbb_module, &system_module, 0, indirect_edge);
    }
    hashcode_lock_release();

#ifdef UNIX
    if (syscall_number == SYS_execve) {
        flush_output_buffers();
    }
#endif
}

void
notify_process_terminating(bool is_crash) {
    CS_LOG("END| Notification of process terminating\n");

    if (CROWD_SAFE_MONITOR()) {
        if (!is_crash)
            hashcode_lock_acquire();
#ifdef MONITOR_UNEXPECTED_IBP
        write_final_uibp_report();
#endif
        if (!is_crash)
            hashcode_lock_release();

        // dr_exit_process(0);
    }

    // altogether too early:
    //if (CROWD_SAFE_MODULE_LOG())
    //    close_crowd_safe_trace();
}

void
destroy_link_observer() {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    CS_LOG("END| Normal exit: destroying link observer.\n");

    if (CROWD_SAFE_NETWORK_MONITOR())
        destroy_network_monitor();

    delete_blacklist();
    ibp_hash_global_destroy();
    destroy_bb_hashtable();
    destroy_crowd_safe_gencode();
    close_basic_block_observer();
    destroy_indirect_link_observer();
    flush_output_buffers();

    destroy_module_observer();
    close_crowd_safe_util();

    dr_global_free(initialized_thread_count, sizeof(int));
    initialized_thread_count = NULL;
    //close_crowd_safe_log();

    hashtable_delete(suspended_shadow_stacks);
    dr_global_free(suspended_shadow_stacks, sizeof(hashtable_t));
}

void
link_observer_thread_exit(dcontext_t *dcontext) {
    crowd_safe_thread_local_t *cstl;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (initialized_thread_count == NULL)
        CS_WARN("Thread exit for dcontext %llx; thread count unavailable because link_observer has been destroyed\n",
            p2int(dcontext));
    else
        CS_DET("Thread exit for dcontext "PFX" on thread %d; currently %dth initialized thread\n",
            p2int(dcontext), current_thread_id(), *initialized_thread_count);

    indirect_link_observer_thread_exit(dcontext);

    cstl = GET_CSTL(dcontext);
    dr_global_free(cstl->stack_walk, sizeof(return_address_iterator_t));
    dr_global_free(cstl, sizeof(crowd_safe_thread_local_t));

    if (initialized_thread_count != NULL)
        (*initialized_thread_count)--;
}

/**** Private Functions ****/

static void
flush_output_buffers() {
#ifdef UNIX
    hashcode_lock_acquire();
    resolve_pending_trampolines();
    hashcode_lock_release();
#endif
}

static void
process_exit(void) {
    close_crowd_safe_trace();
}
