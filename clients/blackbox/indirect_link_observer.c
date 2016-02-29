#include "indirect_link_observer.h"
#include <string.h>
#include "../../core/x86/arch.h"
#include "../../core/x86/instr.h"
#include "../../core/x86/instrument.h"
#include "../../core/x86/instr_create.h"
#include "../../core/heap.h"
#include "../../core/fragment.h"
#include "crowd_safe_util.h"
#include "link_observer.h"
#include "crowd_safe_trace.h"
#include "basic_block_hashtable.h"
#include "execution_monitor.h"
#include "indirect_link_hashtable.h"

#ifdef WINDOWS
# include "winbase.h"
#endif

/**** Private Fields ****/

#define RESOLVED_IMPORTS_COUNT 0x1000
#define RETURN_ADDRESS(shadow_stack) (shadow_stack-1)->return_address

/**** Private Prototypes ****/

static void
report_unexpected_return(dcontext_t *dcontext);

/**** Public Functions ****/

void
init_indirect_link_observer(dcontext_t *dcontext) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

#ifdef WINDOWS
    if (CROWD_SAFE_WDB_SCRIPT(WDB_ANY))
        OutputDebugString("_debug_ .logopen ur.log;g\n");

    resolved_imports = (drvector_t *)CS_ALLOC(sizeof(drvector_t));
    drvector_init(resolved_imports, 1000, false, NULL);
#endif
}

void
indirect_link_observer_thread_init(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
    csd->resolved_imports =
        (resolved_import_t*)CS_ALLOC(RESOLVED_IMPORTS_COUNT * sizeof(resolved_import_t));
    csd->resolved_imports->name = NULL; // put an empty frame at the bottom
    csd->resolved_imports->address = NULL;
    csd->resolved_imports += 1;
#endif

    cstl->shadow_stack_base = HEAP_ARRAY_ALLOC(dcontext, shadow_stack_frame_t, SHADOW_STACK_SIZE,
                                               ACCT_IBLTABLE, UNPROTECTED);
    CS_DET("Allocated shadow stack at "PX"\n", csd->shadow_stack_base);
    csd->shadow_stack = cstl->shadow_stack_base;
    csd->shadow_stack->base_pointer = (app_pc)SHADOW_STACK_SENTINEL;
    csd->shadow_stack->return_address = (app_pc)SHADOW_STACK_EMPTY_TAG;
    csd->shadow_stack += 1;
    csd->shadow_stack_miss_frame = 0ULL;
    csd->stack_spy_mark = 0;

    csd->ibp_data.ibp_from_tag = PC(0);
    csd->ibp_data.ibp_to_tag = PC(0);
    csd->ibp_data.flags = 0UL;
    csd->ibp_data.syscall_from_tag = PC(0);
}

void
indirect_link_hashtable_insert(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    ibp_metadata_t *ibp_data = &csd->ibp_data;
    crowd_safe_thread_local_t *cstl = csd->crowd_safe_thread_local;
    DEBUG_DECLARE(bb_state_t *from_state = NULL;)
    DEBUG_DECLARE(bb_state_t *to_state = NULL;)
    bool add;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    ASSERT(!IBP_STACK_IS_PENDING(ibp_data));
    if (!IBP_PATH_IS_PENDING(ibp_data)) {
        CS_DET("Skip IBP ("PX" - "PX"?) because the path is not pending\n", ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);
        return;
    }
    if (IBP_IS_RETURN(ibp_data) && !IBP_IS_UNEXPECTED_RETURN(ibp_data)) {
        CS_DET("Skip expected return "PX" - "PX"\n", ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);

        clear_pending_ibp(ibp_data);
        return;
    }

    if (ibp_data->ibp_from_tag == 0) {
        CS_ERR("Missing from tag in indirect link to "PX"!\n", ibp_data->ibp_to_tag);
        clear_pending_ibp(ibp_data);
        return;
    }

    /*
    {
        module_location_t *from_module = get_module_for_address(ibp_data->ibp_from_tag);
        module_location_t *to_module = get_module_for_address(ibp_data->ibp_to_tag);

        if (from_module != NULL && to_module != NULL) {
            CS_LOG("IBP| %s("PX") -> %s("PX")\n",
                   from_module->module_name, MODULAR_PC(from_module, ibp_data->ibp_from_tag),
                   to_module->module_name, MODULAR_PC(to_module, ibp_data->ibp_to_tag));

            if (strcmp(from_module->module_name, "perlbench") == 0 &&
                MODULAR_PC(from_module, ibp_data->ibp_from_tag) == int2p(0x154836))
                CS_LOG("boo!\n");
        } else {
            CS_LOG("IBP| "PFX" -> "PFX"\n", ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);
        }
    }
    */

    DODEBUG({
        hashcode_lock_acquire(); {
            from_state = get_bb_state(ibp_data->ibp_from_tag);
            to_state = get_bb_state(ibp_data->ibp_to_tag);
        }
        hashcode_lock_release();

        //ASSERT((from_state != NULL) && IS_BB_LIVE(from_state)); // trace hack!
        ibp_testify(ibp_data->ibp_to_tag);
    });
#ifdef MONITOR_UNEXPECTED_IBP
    if (notify_possibly_unexpected_ibp(dcontext, cstl, ibp_data->ibp_from_tag,
        ibp_data->ibp_to_tag, IBP_IS_UNEXPECTED_RETURN(ibp_data)))
    {
        /*
        fragment_t *from_f = fragment_lookup(dcontext, ibp_data->ibp_from_tag);
        fragment_t *to_f = fragment_lookup(dcontext, ibp_data->ibp_to_tag);

        if (to_f == NULL) {
            CS_ERR("Repeat IBP to tag with no fragment!\n");
        } else if (!TEST(to_f->flags, FRAG_IS_TRACE_HEAD)) {
            CS_LOG("Redundant IBP to non-trace-head "PX"\n", to_f->tag);
        }
        */

        clear_pending_ibp(ibp_data); // already seen this one, so continue without further action
        IBP_SET_META(ibp_data, &, ~IBP_META_UNEXPECTED_RETURN);
        return;
    }
#endif
    add = (ibp_hash_lookup(dcontext, ibp_data->ibp_from_tag, ibp_data->ibp_to_tag) == 0ULL);
    DODEBUG({
        if (!(is_monitor_active() || add) && ((to_state == NULL) || !IS_BB_LIVE(to_state) || !IS_BB_COMMITTED(to_state))) {
            CS_DET("IBP table skipped add "PX" - "PX" when the 'to' state was %s\n", ibp_data->ibp_from_tag,
                ibp_data->ibp_to_tag, (to_state == NULL) ? "null" : IS_BB_LIVE(to_state) ? "not committed" : "out of scope");
        }
    });

    if (add) {
        bool is_return = false, is_expected_return = false;
        DODEBUG(cstl->bb_meta.created_ibp_edge = true;);
        if (IBP_IS_UNEXPECTED_RETURN(ibp_data)) {
            shadow_stack_frame_t *top;
            shadow_stack_frame_t *walk;

            is_return = true;

            // IBL shadow stack unwind is timid in some cases--unwind all the way down
            while ((SHADOW_FRAME(csd)->base_pointer < XSP(dcontext) ||
                    SHADOW_FRAME(csd)->return_address == int2p(SHADOW_STACK_CALLBACK_TAG)) &&
                   (SHADOW_FRAME(csd)->base_pointer != (app_pc)SHADOW_STACK_SENTINEL) &&
                   (ibp_data->ibp_to_tag != SHADOW_FRAME(csd)->return_address))
            {
                csd->shadow_stack--;
                //if (ibp_data->ibp_to_tag == SHADOW_FRAME(csd)->return_address) {
                //    expected = true;
                //}
            }
            top = SHADOW_FRAME(csd); // return went here
            for (walk = top; walk < csd->shadow_stack_miss_frame; walk++) {
                if (walk->return_address == ibp_data->ibp_to_tag) {
                    break;
                }
            }

            if (walk == csd->shadow_stack_miss_frame) {
                for (walk = top; walk < csd->shadow_stack_miss_frame; walk++) {
                    if (walk->return_address == dcontext->next_tag) {
                        break;
                    }
                }
            }

            if (walk == csd->shadow_stack_miss_frame) {
                bb_state_t *state;
                module_location_t *from_module = get_module_for_address(ibp_data->ibp_from_tag);
                module_location_t *to_module = get_module_for_address(ibp_data->ibp_to_tag);

#ifdef DEBUG
                {
                    fragment_t *from_f = fragment_lookup_bb(dcontext, ibp_data->ibp_from_tag);
                    fragment_t *to_f = fragment_lookup_bb(dcontext, ibp_data->ibp_to_tag);
                    fragment_t *last_f = linkstub_fragment(dcontext, dcontext->last_exit);
                    if (from_f != NULL && to_f != NULL && last_f != NULL) {
                        CS_LOG(PX" @"PX" -UR-> "PX" @"PX". Last fragment "PX" @"PX"\n",
                               from_f->tag, from_f->start_pc, to_f->tag, to_f->start_pc, last_f->tag, last_f->start_pc);
                    }
                }
#endif

                CS_DET("Unexpected return anomaly: 'to' address "PX" was never on the stack in %s("PX")->%s("PX")\n",
                       ibp_data->ibp_to_tag, from_module->module_name, ibp_data->ibp_from_tag, to_module->module_name,
                       ibp_data->ibp_to_tag);

                hashcode_lock_acquire();
                state = get_bb_state(ibp_data->ibp_from_tag);
                SET_BB_UNEXPECTED_RETURN(state);
                hashcode_lock_release();

                if (from_module != to_module) {
                    // split the return at the module boundary and write two separate edges, to avoid cross-module chaos
                    walk = top;
                    while (get_module_for_address(walk->return_address) == to_module)
                        walk++;
                    if (get_module_for_address(walk->return_address) != from_module) {
                        CS_DET("Unexpected return anomaly: "PX" (%s) to "PX" (%s) skips over module %s ("PX")!\n",
                            ibp_data->ibp_from_tag, from_module->module_name,
                            ibp_data->ibp_to_tag, to_module->module_name,
                            get_module_for_address(walk->return_address)->module_name, walk->return_address);
                    } else {
                        CS_DET("Split cross-module off-stack unexpected return into two edges: "PX" to "PX" in %s " \
                                "and "PX" to "PX" in %s\n",
                            ibp_data->ibp_from_tag, walk->return_address, from_module->module_name,
                            (walk-1)->return_address, ibp_data->ibp_to_tag, to_module->module_name);
                    }
                }
            } else {
                is_expected_return = true; // it was a tail call unwind
                IBP_SET_META(ibp_data, &, ~IBP_META_UNEXPECTED_RETURN);
                ibp_hash_add(dcontext, ibp_data->ibp_from_tag, ibp_data->ibp_to_tag); // optimize in-cache resolution
            }
            report_unexpected_return(dcontext);
        }

#ifdef SEED_TLS_FOR_IBL_VERIFICATION
        ASSERT(ibp_data->ibp_from_tag == int2p(0x12345678));
#else
        if (!is_expected_return) {
            notify_traversing_fragments(dcontext, ibp_data->ibp_from_tag, ibp_data->ibp_to_tag, 0,
                    is_return ? unexpected_return_edge : indirect_edge);
        }
#endif
        CS_DET("indirect link: "PX" to "PX"\n", ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);
    } else {
        CS_DET("Skipping IBP "PX" - "PX" \n", ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);
    }
    clear_pending_ibp(ibp_data);
}

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
void
harvest_resolved_imports(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    if (RESOLVED_IMPORT_PEEK(csd)->address) {
        int harvest_count = 0;
        hashcode_lock_acquire(); // cs-todo: new private lock for this?

        do {
            resolved_import_t *frame = (resolved_import_t*)CS_ALLOC(sizeof(resolved_import_t));
            if ((uint)RESOLVED_IMPORT_PEEK(csd)->name < 0x4000U) {
                // frame->name = ...allocate--but how to know it needs `free()`?
                // dr_snprintf(fname->name, 16, "%d", (uint)RESOLVED_IMPORT_PEEK(csd)->name);
            } else {
                frame->name = RESOLVED_IMPORT_PEEK(csd)->name; // cs-todo: copy it?
            }

            frame->address = RESOLVED_IMPORT_PEEK(csd)->address;
            drvector_append(resolved_imports, frame);

            CS_DET("Resolved import %s to "PX"\n",
                RESOLVED_IMPORT_PEEK(csd)->name, RESOLVED_IMPORT_PEEK(csd)->address);

            harvest_count++;
            RESOLVED_IMPORT_POP(csd);
        } while (RESOLVED_IMPORT_PEEK(csd)->address);

        if (harvest_count > 0x200)
            CS_WARN("Large harvest of dynamically resolved imports: %d. Check stack limit.\n", harvest_count);

        hashcode_lock_release();
    }
}
#endif

void
push_nested_shadow_stack(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    csd->shadow_stack->return_address = (app_pc)SHADOW_STACK_CALLBACK_TAG;
    csd->shadow_stack->base_pointer = (app_pc)SHADOW_STACK_SENTINEL;
    csd->shadow_stack += 1;

    check_shadow_stack_bounds(csd);
}

void
pop_nested_shadow_stack(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    crowd_safe_thread_local_t *cstl = csd->crowd_safe_thread_local;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    while (csd->shadow_stack->base_pointer != (app_pc)SHADOW_STACK_SENTINEL)
        csd->shadow_stack--;

    if (csd->shadow_stack->return_address != (app_pc)SHADOW_STACK_CALLBACK_TAG) {
        CS_WARN("Shadow stack at "PX" popped to return address "PX" instead of a callback tag!\n",
            SHADOW_FRAME(csd), SHADOW_FRAME(csd)->return_address);
    }
    check_shadow_stack_bounds(csd);
}

void
pop_shadow_stack_frame(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    crowd_safe_thread_local_t *cstl = csd->crowd_safe_thread_local;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    csd->shadow_stack--;
    check_shadow_stack_bounds(csd);
}

void
indirect_link_observer_thread_exit(dcontext_t *dcontext) {
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    HEAP_ARRAY_FREE(dcontext, cstl->shadow_stack_base, shadow_stack_frame_t, SHADOW_STACK_SIZE,
                    ACCT_IBLTABLE, UNPROTECTED);
}

void
destroy_indirect_link_observer() {
#ifdef WINDOWS
    if (CROWD_SAFE_WDB_SCRIPT(WDB_ANY))
        OutputDebugString("_debug_ .logclose;g\n");
#endif
}

/**** Private Functions ****/

static inline void
report_unexpected_return(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    ibp_metadata_t *ibp_data = &csd->ibp_data;
    shadow_stack_frame_t *f = csd->shadow_stack_miss_frame;
    module_location_t *from_module = get_module_for_address(ibp_data->ibp_from_tag);
    module_location_t *to_module = get_module_for_address(ibp_data->ibp_to_tag);
    module_location_t *miss_module = get_module_for_address(RETURN_ADDRESS(f));
    char *scope_name;
#ifdef WINDOWS
    char debug_buffer[1024];
    char symbol_buffer[32];
#endif

    if (from_module != to_module)
        scope_name = "Cross-module";
    else
        scope_name = "Intra-module";

    CS_DET("%s unexpected return from %s("PX") to %s("PX"), missing %s("PX")\n",
        scope_name,
        from_module->module_name, MODULAR_PC(from_module, ibp_data->ibp_from_tag),
        to_module->module_name, MODULAR_PC(to_module, ibp_data->ibp_to_tag),
        miss_module->module_name, MODULAR_PC(miss_module, RETURN_ADDRESS(f)));

#ifdef WINDOWS
    if (CROWD_SAFE_WDB_SCRIPT(WDB_UR_SYMBOLS)) {
        ASSERT(!(ibp_data->ibp_from_tag == RETURN_ADDRESS(f) && (ibp_data->ibp_to_tag == RETURN_ADDRESS(f-1))));

        dr_snprintf(debug_buffer, 1023, "_debug_ .echo \"Unexpected return from "PX" to "PX"\";",
            ibp_data->ibp_from_tag, ibp_data->ibp_to_tag);
        dr_snprintf(symbol_buffer, 31, "ln "PX";", ibp_data->ibp_from_tag);
        strcat(debug_buffer, symbol_buffer);

        while (f > csd->shadow_stack) {
            if ((RETURN_ADDRESS(f) != ibp_data->ibp_from_tag) && (RETURN_ADDRESS(f) != ibp_data->ibp_to_tag)) {
                dr_snprintf(symbol_buffer, 31, "ln "PX";", RETURN_ADDRESS(f));
                strcat(debug_buffer, symbol_buffer);
            }
            f--;
        }

        dr_snprintf(symbol_buffer, 31, "ln "PX";", ibp_data->ibp_to_tag);
        strcat(debug_buffer, symbol_buffer);

        strcat(debug_buffer, "g");
        OutputDebugString(debug_buffer);
    }
#endif
}
