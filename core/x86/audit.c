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
#include "audit.h"

#ifdef SECURITY_AUDIT /* around whole file */

static void
audit_noop();

static audit_callbacks_t default_audit_callbacks = {
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
    audit_noop, audit_noop, audit_noop, audit_noop, audit_noop,
};

audit_callbacks_t *audit_callbacks = &default_audit_callbacks;

DR_API
void
dr_enter_fcache(dcontext_t *dcontext, fcache_enter_func_t entry, cache_pc pc)
{
    enter_fcache(dcontxt, entry, pc);
}

DR_API
void
dr_register_audit_callbacks(audit_callbacks_t *callbacks)
{
    audit_callbacks = callbacks;
}

static void
audit_noop()
{
}

#endif /* SECURITY_AUDIT */
