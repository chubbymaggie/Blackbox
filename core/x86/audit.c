/* **********************************************************
 * Copyright (c) 2016 UCI PLRG.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "../globals.h"
#include "../fragment.h"
#include "../link.h"
#include "audit.h"

#ifdef SECURITY_AUDIT /* around whole file */

audit_callbacks_t *audit_callbacks = NULL;

DR_API
void
dr_enter_fcache(dcontext_t *dcontext, app_pc pc)
{
    fcache_enter_func_t fcache_enter;
    fragment_t *f = fragment_lookup(dcontext, ibp_data->ibp_to_tag);

    if (TEST(FRAG_SHARED, f->flags))
        fcache_enter = get_fcache_enter_shared_routine(dcontext);
    else
        fcache_enter = get_fcache_enter_private_routine(dcontext);

    enter_fcache(dcontext, fcache_enter, FCACHE_ENTRY_PC(f));
}

DR_API
void
dr_register_audit_callbacks(audit_callbacks_t *callbacks)
{
    audit_callbacks = callbacks;
}

DR_API
app_pc
dcontext_get_next_tag(dcontext_t *dcontext)
{
    return dcontext->next_tag;
}

DR_API
byte *
dr_get_ntdll_proc_address(const char *name)
{
    return get_proc_address(get_ntdll_base(), name);
}

DR_API
local_security_audit_state_t *
dcontext_get_audit_state(dcontext_t *dcontext)
{
    return &((local_state_extended_t *) dcontext->local_state)->security_audit_state;
}

DR_API
ibp_metadata_t *
dcontext_get_ibp_data(dcontext_t *dcontext)
{
    return &dcontext_get_audit_state(dcontext)->ibp_data;
}

DR_API
app_pc
dr_get_building_trace_tail(dcontext_t *dcontext, bool *is_return, app_pc *trace_tag)
{
    if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit) &&
        is_building_trace(dcontext)) {
        monitor_data_t *md = (monitor_data_t *) dcontext->monitor_field;

        if (is_return != NULL)
            *is_return = TEST(LINK_RETURN, md->final_exit_flags);
        if (trace_tag != NULL)
            *trace_tag = md->trace_tag;

        return md->blk_info[md->num_blks-1].info.tag;
    } else {
        return NULL;
    }
}

DR_API
byte
dr_fragment_find_direct_ordinal(fragment_t *from, app_pc to) {
    linkstub_t *l;
    byte exit_ordinal = 0x0;

    for (l = FRAGMENT_EXIT_STUBS(from); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (LINKSTUB_DIRECT(l->flags) && (((direct_linkstub_t*)l)->target_tag == to)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    SEC_LOG(4, "Could not find the correct exit ordinal for direct link from tag "PX"\n",
            from->tag);
    return 0xFF;
}

DR_API
byte
dr_fragment_find_indirect_ordinal(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (LINKSTUB_INDIRECT(l->flags)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    return 0xff;
}

DR_API
byte
dr_fragment_find_call_ordinal(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (LINKSTUB_SPECIAL(l->flags))
            continue;
        if (TEST(LINK_CALL, l->flags)) {
            return exit_ordinal;
        }
        exit_ordinal++;
    }

    return 0xff;
}

DR_API
byte
dr_fragment_count_ordinals(fragment_t *f) {
    linkstub_t *l;
    byte exit_ordinal = 0;

    for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l)) {
        if (!LINKSTUB_SPECIAL(l->flags))
            exit_ordinal++;
        if (TEST(LINK_CALL, l->flags))
            exit_ordinal++; // one more for the call continuation
    }

    return exit_ordinal;
}

DR_API
void
dr_fragment_log_ordinals(dcontext_t *dcontext, app_pc tag,
                         const char *line_prefix, uint loglevel)
{
    fragment_t *f = fragment_lookup(dcontext, from);
    if (f != NULL) {
        linkstub_t *l;
        byte exit_ordinal = 0x0;

        for (l = FRAGMENT_EXIT_STUBS(f); l; l = LINKSTUB_NEXT_EXIT(l), exit_ordinal++) {
            if (LINKSTUB_DIRECT(l->flags)) {
                SEC_LOG(loglevel, "%s#%d to "PX" flags: 0x%x; cti offset: "PX"\n",
                        line_prefix, exit_ordinal, ((direct_linkstub_t*)l)->target_tag,
                        l->flags, l->cti_offset);
            } else {
                SEC_LOG(loglevel, "%s#%d flags: 0x%x; cti offset: "PX"\n", line_prefix,
                        exit_ordinal, l->flags, l->cti_offset);
            }
        }
    }
}

DR_API
void
dr_log_ibp_state(dcontext_t *dcontext, uint loglevel)
{
    ibp_metadata_t *ibp_data = dcontext_get_ibp_data(dcontext);
    fragment_t *from_f = fragment_lookup_bb(dcontext, ibp_data->ibp_from_tag);
    fragment_t *to_f = fragment_lookup_bb(dcontext, ibp_data->ibp_to_tag);
    fragment_t *last_f = linkstub_fragment(dcontext, dcontext->last_exit);
    if (from_f != NULL && to_f != NULL && last_f != NULL) {
        SEC_LOG(loglevel, PX" @"PX" -UR-> "PX" @"PX". Last fragment "PX" @"PX"\n",
                from_f->tag, from_f->start_pc, to_f->tag, to_f->start_pc,
                last_f->tag, last_f->start_pc);
    }
}

DR_API
void
dr_log_last_exit(dcontext_t *dcontext, const char *prefix, uint loglevel)
{
    linkstub_t *l;

    SEC_LOG(loglevel, "%s%sbuilding trace\n", prefix,
            is_building_trace(dcontext) ? "" : "not ");

    if (is_ibl_sourceless_linkstub((const linkstub_t*) dcontext->last_exit)) {
        dr_fragment_t *last_f = dcontext->last_fragment;
        dr_fragment_t *in_f = linkstub_fragment(dcontext, dcontext->last_exit);

        SEC_LOG(loglevel, "%sIndirect exit for %s %s: "PX".\n", prefix,
                last_f == NULL ? 0 : TEST(FRAG_IS_TRACE, last_f->flags) ? "trace" : "bb",
                TEST(LINK_RETURN, dcontext->last_exit->flags) ? "ret" :
                EXIT_IS_CALL(dcontext->last_exit->flags) ? "call*" : "jmp*",
                in_f == NULL ? (last_f == NULL ? 0 : last_f->tag) : in_f->tag);
    }

    for (l = f->in_xlate.incoming_stubs; l != NULL; l = LINKSTUB_NEXT_INCOMING(l)) {
        dr_fragment_t *in_f = linkstub_fragment(dcontext, l);
        SEC_LOG(loglevel, "%sFound a linkstub from "PX" with flags 0x%x\n", prefix,
                in_f->tag, l->flags);
    }
}

#endif /* SECURITY_AUDIT */
