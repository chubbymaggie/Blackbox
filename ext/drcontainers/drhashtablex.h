/* **********************************************************
 * Copyright (c) 2011-2013 Google, Inc.  All rights reserved.
 * Copyright (c) 2007-2010 VMware, Inc.  All rights reserved.
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

/* Containers DynamoRIO Extension: Hashtable */

#ifdef WINDOWS
# define _CRT_SECURE_NO_DEPRECATE 1
#endif

#include "containers_private.h"
#ifdef UNIX
# include <string.h>
#endif
#include <stddef.h> /* offsetof */

#ifndef HASHTABLE_NAME_KEY
# define HASHTABLE_NAME_KEY hashtable
#endif
#define NAME_KEY HASHTABLE_NAME_KEY

#ifdef HASHTABLE_KEY_TYPE
# define CUSTOM_KEY_TYPE 1
#else
# define HASHTABLE_KEY_TYPE void*
# define HASHTABLE_KEY_IS_POINTER 1
#endif
#define KEY_TYPE HASHTABLE_KEY_TYPE
#ifdef HASHTABLE_KEY_IS_POINTER
# define KEY_IS_POINTER 1
#endif

#ifdef HASHTABLE_PAYLOAD_TYPE
# define CUSTOM_PAYLOAD_TYPE 1
#endif

#ifndef HASHTABLE_PAYLOAD_TYPE
# define HASHTABLE_PAYLOAD_TYPE void*
# define HASHTABLE_PAYLOAD_IS_POINTER 1
#endif
#define PAYLOAD_TYPE HASHTABLE_PAYLOAD_TYPE

#ifdef HASHTABLE_PAYLOAD_IS_POINTER
# define HASHTABLE_IS_EMPTY(x) ((x) == NULL)
# define HASHTABLE_INIT_EMPTY NULL
# define _IF_PAYLOAD_INLINE(x)
#else
# define _IF_PAYLOAD_INLINE(x) x
#endif

#ifndef HASHTABLE_ALLOCATOR
 #define HASHTABLE_ALLOCATOR dr_global_alloc
#endif
#ifndef HASHTABLE_DEALLOCATOR
 #define HASHTABLE_DEALLOCATOR dr_global_free
#endif

#define HASHTABLE_EXPAND_KEY(pre, key, post) pre##key##post
#define HASHTABLE_NAME(pre, name, post) HASHTABLE_EXPAND_KEY(pre, name, post)
#define HASHTABLE_TYPE HASHTABLE_NAME(,NAME_KEY,_t)

#ifdef DEBUG
# define IF_DEBUG(x) x
#else
# define IF_DEBUG(x) /* nothing */
#endif

/* check if all bits in mask are set in var */
#define TESTALL(mask, var) (((mask) & (var)) == (mask))
/* check if any bit in mask is set in var */
#define TESTANY(mask, var) (((mask) & (var)) != 0)
/* check if a single bit is set in var */
#define TEST TESTANY

/***************************************************************************
 * UTILITIES
 */

/*
#ifdef UNIX
/ * FIXME: i#30: provide safe libc routines like we do on Windows * /
static int
tolower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return (c - ('A' - 'a'));
    return c;
}
#endif
*/

bool
HASHTABLE_NAME(,NAME_KEY,_stri_eq)(const char *s1, const char *s2)
{
    char uc1, uc2;
    if (s1 == NULL || s2 == NULL)
        return false;
    do {
        if (*s1 == '\0') {
            if (*s2 == '\0')
                return true;
            return false;
        }
        uc1 = ((*s1 >= 'A') && (*s1 <= 'Z')) ? (*s1 + 'a' - 'A') : *s1;
        uc2 = ((*s2 >= 'A') && (*s2 <= 'Z')) ? (*s2 + 'a' - 'A') : *s2;
        s1++;
        s2++;
    } while (uc1 == uc2);
    return false;
}

/***************************************************************************
 * HASHTABLE
 *
 * Supports both app_pc and string keys.
 */

/* We parametrize heap and assert for use in multiple libraries */
static PAYLOAD_TYPE (* HASHTABLE_NAME(,NAME_KEY,_alloc_func) )(size_t);
static void (* HASHTABLE_NAME(,NAME_KEY,_free_func) )(PAYLOAD_TYPE, size_t);
static void (* HASHTABLE_NAME(,NAME_KEY,_assert_fail_func) )(const char *);

/* If no assert func is registered we just abort since we don't know
 * how to log or print (could msgbox on windows I suppose).
 * If an assert func is registered, we don't want the complexity of
 * sprintf so we give up on providing the file+line for hashtable.c but
 * the msg should identify the source.
 */
#ifdef WINDOWS
# define IF_WINDOWS(x) x
#else
# define IF_WINDOWS(x)
#endif

#ifdef DEBUG
# define EXT_ASSERT(x, msg) do { \
    if (!(x)) { \
        if (HASHTABLE_NAME(,NAME_KEY,_assert_fail_func) != NULL) { \
            (*HASHTABLE_NAME(,NAME_KEY,_assert_fail_func))(msg); \
        } else { \
            dr_fprintf(STDERR, "EXT_ASSERT FAILURE: %s:%d: %s (%s)", \
                       __FILE__,  __LINE__, #x, msg); \
            IF_WINDOWS(dr_messagebox("EXT_ASSERT FAILURE: %s:%d: %s (%s)", \
                                     __FILE__,  __LINE__, #x, msg);) \
            dr_abort(); \
        } \
    } \
} while (0)
#else
# define EXT_ASSERT(x, msg) /* nothing */
#endif


/* To support use in other libraries we allow parametrization */
void
HASHTABLE_NAME(,NAME_KEY,_global_config)(PAYLOAD_TYPE(*alloc_fptr)(size_t), void (*free_fptr)(PAYLOAD_TYPE, size_t),
                        void (*assert_fail_fptr)(const char *))
{
    HASHTABLE_NAME(,NAME_KEY,_alloc_func) = alloc_fptr;
    HASHTABLE_NAME(,NAME_KEY,_free_func) = free_fptr;
    HASHTABLE_NAME(,NAME_KEY,_assert_fail_func) = assert_fail_fptr;
}

static void
HASHTABLE_NAME(,NAME_KEY,_hash_free)(void *ptr, size_t size)
{
#ifndef CUSTOM_PAYLOAD_TYPE
    if (HASHTABLE_NAME(,NAME_KEY,_free_func) != NULL)
        (*HASHTABLE_NAME(,NAME_KEY,_free_func))(ptr, size);
    else
        dr_global_free(ptr, size);
#endif
}


#define EXT_HASH_MASK(num_bits) ((~0U)>>(32-(num_bits)))
#define EXT_HASH_FUNC_BITS(val, num_bits) ((val) & (EXT_HASH_MASK(num_bits)))
#define EXT_HASH_FUNC(val, mask) ((val) & (mask))

static uint
HASHTABLE_NAME(,NAME_KEY,_hash_key)(HASHTABLE_TYPE *table, KEY_TYPE key)
{
    uint hash = 0;
#ifdef KEY_IS_POINTER
    if (table->hash_key_func != NULL) {
        hash = table->hash_key_func(key);
    } else if (table->hashtype == HASH_STRING || table->hashtype == HASH_STRING_NOCASE) {
        const char *s = (const char *) key;
        char c;
        uint i, shift;
        uint max_shift = ALIGN_FORWARD(table->table_bits, 8);
        /* XXX: share w/ core's hash_value() function */
        for (i = 0; s[i] != '\0'; i++) {
            c = s[i];
            if (table->hashtype == HASH_STRING_NOCASE)
                c = (char) tolower(c);
            shift = (i % 4) * 8;
            if (shift > max_shift)
                shift = max_shift;
            hash ^= c << shift;
        }
    } else {
#endif
        /* HASH_INTPTR, or fallback for HASH_CUSTOM in release build */
        EXT_ASSERT(table->hashtype == HASH_INTPTR,
               "hashtable.c hash_key internal error: invalid hash type");
        hash = (uint)(ptr_uint_t) key;
#ifdef KEY_IS_POINTER
    }
#endif
    return EXT_HASH_FUNC_BITS(hash, table->table_bits);
}

static bool
HASHTABLE_NAME(,NAME_KEY,_keys_equal)(HASHTABLE_TYPE *table, KEY_TYPE key1, KEY_TYPE key2)
{
#ifdef KEY_IS_POINTER
    if (table->cmp_key_func != NULL)
        return table->cmp_key_func(key1, key2);
    else if (table->hashtype == HASH_STRING)
        return strcmp((const char *) key1, (const char *) key2) == 0;
    else if (table->hashtype == HASH_STRING_NOCASE)
        return HASHTABLE_NAME(,NAME_KEY,_stri_eq)((const char *) key1, (const char *) key2);
    else {
#endif
        /* HASH_INTPTR, or fallback for HASH_CUSTOM in release build */
        EXT_ASSERT(table->hashtype == HASH_INTPTR,
               "hashtable.c keys_equal internal error: invalid hash type");
        return key1 == key2;
#ifdef KEY_IS_POINTER
    }
#endif
}

void
HASHTABLE_NAME(,NAME_KEY,_init_ex)(HASHTABLE_TYPE *table, uint num_bits, hash_type_t hashtype, bool str_dup,
                  bool synch, void (*free_payload_func)(PAYLOAD_TYPE),
                  uint (*hash_key_func)(KEY_TYPE), bool (*cmp_key_func)(KEY_TYPE, KEY_TYPE))
{
    HASHTABLE_NAME(,NAME_KEY,_entry_t) **alloc = (HASHTABLE_NAME(,NAME_KEY,_entry_t) **)
        HASHTABLE_ALLOCATOR((size_t)HASHTABLE_SIZE(num_bits) * sizeof(HASHTABLE_NAME(,NAME_KEY,_entry_t)*));
    memset(alloc, 0, (size_t)HASHTABLE_SIZE(num_bits) * sizeof(HASHTABLE_NAME(,NAME_KEY,_entry_t)*));
    table->table = alloc;
    table->hashtype = hashtype;
    table->str_dup = str_dup;
    EXT_ASSERT(!str_dup || hashtype == HASH_STRING || hashtype == HASH_STRING_NOCASE,
           "hashtable_init_ex internal error: invalid hashtable type");
    table->lock = dr_mutex_create();
    table->table_bits = num_bits;
    table->synch = synch;
    table->free_payload_func = free_payload_func;
    table->hash_key_func = hash_key_func;
    table->cmp_key_func = cmp_key_func;
    EXT_ASSERT(table->hashtype != HASH_CUSTOM ||
           (table->hash_key_func != NULL && table->cmp_key_func != NULL),
           "hashtable_init_ex missing cmp/hash key func");
    table->entries = 0;
    table->config.size = sizeof(table->config);
    table->config.resizable = true;
    table->config.resize_threshold = 75;
}

void
HASHTABLE_NAME(,NAME_KEY,_init)(HASHTABLE_TYPE *table, uint num_bits, hash_type_t hashtype, bool str_dup)
{
    HASHTABLE_NAME(,NAME_KEY,_init_ex)(table, num_bits, hashtype, str_dup, true, NULL, NULL, NULL);
}

void
HASHTABLE_NAME(,NAME_KEY,_configure)(HASHTABLE_TYPE *table, hashtable_config_t *config)
{
    EXT_ASSERT(table != NULL && config != NULL, "invalid params");
    /* Ignoring size of field: shouldn't be in between */
    if (config->size > offsetof(hashtable_config_t, resizable))
        table->config.resizable = config->resizable;
    if (config->size > offsetof(hashtable_config_t, resize_threshold))
        table->config.resize_threshold = config->resize_threshold;
}

void
HASHTABLE_NAME(,NAME_KEY,_lock)(HASHTABLE_TYPE *table)
{
    dr_mutex_lock(table->lock);
}

void
HASHTABLE_NAME(,NAME_KEY,_unlock)(HASHTABLE_TYPE *table)
{
    dr_mutex_unlock(table->lock);
}

/* Lookup an entry by key and return a pointer to the corresponding entry
 * Returns NULL if no such entry exists */
PAYLOAD_TYPE _IF_PAYLOAD_INLINE(*)
HASHTABLE_NAME(,NAME_KEY,_lookup)(HASHTABLE_TYPE *table, KEY_TYPE key)
{
    PAYLOAD_TYPE _IF_PAYLOAD_INLINE(*)res = NULL;
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e;
    uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, key);
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex]; e != NULL; e = e->next) {
        if (HASHTABLE_NAME(,NAME_KEY,_keys_equal)(table, e->key, key)) {
            res = _IF_PAYLOAD_INLINE(&) (e->payload);
            break;
        }
    }
    if (table->synch)
        dr_mutex_unlock(table->lock);
    return res;
}

/* convenience version for inline entries */
#ifndef HASHTABLE_PAYLOAD_IS_POINTER
PAYLOAD_TYPE
HASHTABLE_NAME(,NAME_KEY,_lookup_value)(HASHTABLE_TYPE *table, KEY_TYPE key)
{
    PAYLOAD_TYPE res = HASHTABLE_INIT_EMPTY;
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e;
    uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, key);
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex]; e != NULL; e = e->next) {
        if (HASHTABLE_NAME(,NAME_KEY,_keys_equal)(table, e->key, key)) {
            res = e->payload;
            break;
        }
    }
    if (table->synch)
        dr_mutex_unlock(table->lock);
    return res;
}
#endif

/* caller must hold lock */
static bool
HASHTABLE_NAME(,NAME_KEY,_check_for_resize)(HASHTABLE_TYPE *table)
{
    size_t capacity = (size_t) HASHTABLE_SIZE(table->table_bits);
    if (table->config.resizable &&
        /* avoid fp ops.  should check for overflow. */
        table->entries * 100 > table->config.resize_threshold * capacity) {
        HASHTABLE_NAME(,NAME_KEY,_entry_t) **new_table;
        size_t new_sz;
        uint i, old_bits;
        /* double the size */
        old_bits = table->table_bits;
        table->table_bits++;
        new_sz = (size_t) HASHTABLE_SIZE(table->table_bits) * sizeof(HASHTABLE_NAME(,NAME_KEY,_entry_t)*);
        new_table = (HASHTABLE_NAME(,NAME_KEY,_entry_t) **) HASHTABLE_ALLOCATOR(new_sz);
        memset(new_table, 0, new_sz);
        /* rehash the old table into the new */
        for (i = 0; i < HASHTABLE_SIZE(old_bits); i++) {
            HASHTABLE_NAME(,NAME_KEY,_entry_t) *e = table->table[i];
            while (e != NULL) {
                HASHTABLE_NAME(,NAME_KEY,_entry_t) *nexte = e->next;
                uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, e->key);
                e->next = new_table[hindex];
                new_table[hindex] = e;
                e = nexte;
            }
        }
        HASHTABLE_NAME(,NAME_KEY,_hash_free)(table->table, capacity * sizeof(HASHTABLE_NAME(,NAME_KEY,_entry_t)*));
        table->table = new_table;
        return true;
    }
    return false;
}

bool
HASHTABLE_NAME(,NAME_KEY,_add)(HASHTABLE_TYPE *table, KEY_TYPE key, PAYLOAD_TYPE payload)
{
    uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, key);
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e;
    /* if payload is null can't tell from lookup miss */
    DR_ASSERT(!HASHTABLE_IS_EMPTY(payload));
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex]; e != NULL; e = e->next) {
        if (HASHTABLE_NAME(,NAME_KEY,_keys_equal)(table, e->key, key)) {
            /* we have a use where payload != existing entry so we don't assert on that */
            if (table->synch)
                dr_mutex_unlock(table->lock);
            return false;
        }
    }
    e = (HASHTABLE_NAME(,NAME_KEY,_entry_t) *) HASHTABLE_ALLOCATOR(sizeof(*e));
#ifdef KEY_IS_POINTER
    if (table->str_dup) {
        const char *s = (const char *) key;
        e->key = HASHTABLE_ALLOCATOR(strlen(s)+1);
        strncpy((char *)e->key, s, strlen(s)+1);
    } else
#endif
        e->key = key;
    e->payload = payload;
    e->next = table->table[hindex];
    table->table[hindex] = e;
    table->entries++;
    HASHTABLE_NAME(,NAME_KEY,_check_for_resize)(table);
    if (table->synch)
        dr_mutex_unlock(table->lock);
    return true;
}

PAYLOAD_TYPE _IF_PAYLOAD_INLINE(*)
HASHTABLE_NAME(,NAME_KEY,_add_replace)(HASHTABLE_TYPE *table, KEY_TYPE key, PAYLOAD_TYPE payload)
{
    PAYLOAD_TYPE old_payload = HASHTABLE_INIT_EMPTY;
    uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, key);
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e, *new_e, *prev_e;
    /* if payload is null can't tell from lookup miss */
#ifndef CUSTOM_PAYLOAD_TYPE
    EXT_ASSERT(payload != NULL, "hashtable_add_replace internal error");
#endif
    new_e = (HASHTABLE_NAME(,NAME_KEY,_entry_t) *) HASHTABLE_ALLOCATOR(sizeof(*new_e));
#ifdef KEY_IS_POINTER
    if (table->str_dup) {
        const char *s = (const char *) key;
        new_e->key = HASHTABLE_ALLOCATOR(strlen(s)+1);
        strncpy((char *)new_e->key, s, strlen(s)+1);
    } else
#endif
        new_e->key = key;
    new_e->payload = payload;
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex], prev_e = NULL; e != NULL; prev_e = e, e = e->next) {
        if (HASHTABLE_NAME(,NAME_KEY,_keys_equal)(table, e->key, key)) {
            if (prev_e == NULL)
                table->table[hindex] = new_e;
            else
                prev_e->next = new_e;
            new_e->next = e->next;
#ifdef KEY_IS_POINTER
            if (table->str_dup)
                HASHTABLE_NAME(,NAME_KEY,_hash_free)(e->key, strlen((const char *)e->key) + 1);
#endif
            /* up to caller to free payload */
            old_payload = e->payload;
            HASHTABLE_NAME(,NAME_KEY,_hash_free)(e, sizeof(*e));
            break;
        }
    }
    if (HASHTABLE_IS_EMPTY(old_payload)) {
        new_e->next = table->table[hindex];
        table->table[hindex] = new_e;
        table->entries++;
        HASHTABLE_NAME(,NAME_KEY,_check_for_resize)(table);
    }
    if (table->synch)
        dr_mutex_unlock(table->lock);
#ifdef HASHTABLE_PAYLOAD_IS_POINTER
    return old_payload;
#else
    return &(new_e->payload); // cs-todo: shouldn't the caller get the old payload?
#endif
}

bool
HASHTABLE_NAME(,NAME_KEY,_remove)(HASHTABLE_TYPE *table, KEY_TYPE key)
{
    bool res = false;
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e, *prev_e;
    uint hindex = HASHTABLE_NAME(,NAME_KEY,_hash_key)(table, key);
    if (table->synch)
        dr_mutex_lock(table->lock);
    for (e = table->table[hindex], prev_e = NULL; e != NULL; prev_e = e, e = e->next) {
        if (HASHTABLE_NAME(,NAME_KEY,_keys_equal)(table, e->key, key)) {
            if (prev_e == NULL)
                table->table[hindex] = e->next;
            else
                prev_e->next = e->next;
#ifdef KEY_IS_POINTER
            if (table->str_dup)
                HASHTABLE_NAME(,NAME_KEY,_hash_free)(e->key, strlen((const char *)e->key) + 1);
#endif
            if (table->free_payload_func != NULL)
                (table->free_payload_func)(e->payload);
            HASHTABLE_NAME(,NAME_KEY,_hash_free)(e, sizeof(*e));
            res = true;
            table->entries--;
            break;
        }
    }
    if (table->synch)
        dr_mutex_unlock(table->lock);
    return res;
}

bool
HASHTABLE_NAME(,NAME_KEY,_remove_range)(HASHTABLE_TYPE *table, KEY_TYPE start, KEY_TYPE end)
{
    bool res = false;
    uint i;
    HASHTABLE_NAME(,NAME_KEY,_entry_t) *e, *prev_e, *next_e;
    if (table->synch)
        HASHTABLE_NAME(,NAME_KEY,_lock)(table);
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        for (e = table->table[i], prev_e = NULL; e != NULL; e = next_e) {
            next_e = e->next;
            if (e->key >= start && e->key < end) {
                if (prev_e == NULL)
                    table->table[i] = e->next;
                else
                    prev_e->next = e->next;
#ifdef KEY_IS_POINTER
                if (table->str_dup)
                    HASHTABLE_NAME(,NAME_KEY,_hash_free)(e->key, strlen((const char *)e->key) + 1);
#endif
                if (table->free_payload_func != NULL)
                    (table->free_payload_func)(e->payload);
                HASHTABLE_NAME(,NAME_KEY,_hash_free)(e, sizeof(*e));
                table->entries--;
                res = true;
            } else
                prev_e = e;
        }
    }
    if (table->synch)
        HASHTABLE_NAME(,NAME_KEY,_unlock)(table);
    return res;
}

static void
HASHTABLE_NAME(,NAME_KEY,_clear_internal)(HASHTABLE_TYPE *table)
{
    uint i;
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        HASHTABLE_NAME(,NAME_KEY,_entry_t) *e = table->table[i];
        while (e != NULL) {
            HASHTABLE_NAME(,NAME_KEY,_entry_t) *nexte = e->next;
#ifdef KEY_IS_POINTER
            if (table->str_dup)
                HASHTABLE_NAME(,NAME_KEY,_hash_free)(e->key, strlen((const char *)e->key) + 1);
#endif
            if (table->free_payload_func != NULL)
                (table->free_payload_func)(e->payload);
            HASHTABLE_NAME(,NAME_KEY,_hash_free)(e, sizeof(*e));
            e = nexte;
        }
        table->table[i] = NULL;
    }
    table->entries = 0;
}

void
HASHTABLE_NAME(,NAME_KEY,_clear)(HASHTABLE_TYPE *table)
{
    if (table->synch)
        dr_mutex_lock(table->lock);
    HASHTABLE_NAME(,NAME_KEY,_clear_internal)(table);
    if (table->synch)
        dr_mutex_unlock(table->lock);
}

void
HASHTABLE_NAME(,NAME_KEY,_delete)(HASHTABLE_TYPE *table)
{
    if (table->synch)
        dr_mutex_lock(table->lock);
    HASHTABLE_NAME(,NAME_KEY,_clear_internal)(table);
    HASHTABLE_NAME(,NAME_KEY,_hash_free)(table->table, (size_t)HASHTABLE_SIZE(table->table_bits) *
              sizeof(HASHTABLE_NAME(,NAME_KEY,_entry_t)*));
    table->table = NULL;
    table->entries = 0;
    if (table->synch)
        dr_mutex_unlock(table->lock);
    dr_mutex_destroy(table->lock);
}

#if !defined(CUSTOM_KEY_TYPE) && !defined(CUSTOM_PAYLOAD_TYPE)
/***************************************************************************
 * PERSISTENCE
 */

/* Persists a table of single-alloc entries (i.e., does a shallow
 * copy).  The model here is that the user is using a global table and
 * reading in all the persisted entries into the live table at
 * resurrect time, rather than splitting up the table and using the
 * read-only mmapped portion when live (note that DR has the latter
 * approach for some of its tables and its built-in persistence
 * support in hashtablex.h).  Thus, we write the count and then the
 * entries (key followed by payload) collapsed into an array.
 *
 * Note that we assume the caller is synchronizing across the call to
 * hashtable_persist_size() and hashtable_persist().  If these
 * are called using DR's persistence interface, DR guarantees
 * synchronization.
 *
 * If size > 0 and the table uses HASH_INTPTR keys, these routines
 * only persist those entries with keys in [start..start+size).
 * Pass 0 for size to persist all entries.
 */

static bool
HASHTABLE_NAME(,NAME_KEY,_key_in_range)(HASHTABLE_TYPE *table, HASHTABLE_NAME(,NAME_KEY,_entry_t) *he, ptr_uint_t start, size_t size)
{
    if (table->hashtype != HASH_INTPTR || size == 0)
        return true;
    /* avoiding overflow by subtracting one */
    return ((ptr_uint_t)he->key >= start && (ptr_uint_t)he->key <= (start + (size - 1)));
}

static bool
HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(file_t fd, void *ptr, size_t sz)
{
    return (dr_write_file(fd, ptr, sz) == (ssize_t)sz);
}

size_t
HASHTABLE_NAME(,NAME_KEY,_persist_size)(void *drcontext, HASHTABLE_TYPE *table, size_t entry_size,
                       void *perscxt, hasthable_persist_flags_t flags)
{
    uint count = 0;
    if (table->hashtype == HASH_INTPTR &&
        TESTANY(DR_HASHPERS_ONLY_IN_RANGE | DR_HASHPERS_ONLY_PERSISTED, flags)) {
        /* synch is already provided */
        uint i;
        ptr_uint_t start = 0;
        size_t size = 0;
        if (perscxt != NULL) {
            start = (ptr_uint_t) dr_persist_start(perscxt);
            size = dr_persist_size(perscxt);
        }
        count = 0;
        for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
            HASHTABLE_NAME(,NAME_KEY,_entry_t) *he;
            for (he = table->table[i]; he != NULL; he = he->next) {
                if ((!TEST(DR_HASHPERS_ONLY_IN_RANGE, flags) ||
                     HASHTABLE_NAME(,NAME_KEY,_key_in_range)(table, he, start, size)) &&
                    (!TEST(DR_HASHPERS_ONLY_PERSISTED, flags) ||
                     dr_fragment_persistable(drcontext, perscxt, he->key)))
                    count++;
            }
        }
    } else
        count = table->entries;
    /* we could have an OUT count param that user must pass to hashtable_persist,
     * but that's actually a pain for the user when persisting multiple tables,
     * and usage should always call hashtable_persist() right after calling
     * hashtable_persist_size().
     */
    table->persist_count = count;
    return sizeof(count) +
        (TEST(DR_HASHPERS_REBASE_KEY, flags) ? sizeof(ptr_uint_t) : 0) +
        count * (entry_size + sizeof(PAYLOAD_TYPE));
}

bool
HASHTABLE_NAME(,NAME_KEY,_persist)(void *drcontext, HASHTABLE_TYPE *table, size_t entry_size,
                  file_t fd, void *perscxt, hasthable_persist_flags_t flags)
{
    uint i;
    ptr_uint_t start = 0;
    size_t size = 0;
    IF_DEBUG(uint count_check = 0;)
    if (TEST(DR_HASHPERS_REBASE_KEY, flags) && perscxt == NULL)
        return false; /* invalid params */
    if (perscxt != NULL) {
        start = (ptr_uint_t) dr_persist_start(perscxt);
        size = dr_persist_size(perscxt);
    }
    if (!HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(fd, &table->persist_count, sizeof(table->persist_count)))
        return false;
    if (TEST(DR_HASHPERS_REBASE_KEY, flags)) {
        if (!HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(fd, &start, sizeof(start)))
            return false;
    }
    /* synch is already provided */
    for (i = 0; i < HASHTABLE_SIZE(table->table_bits); i++) {
        HASHTABLE_NAME(,NAME_KEY,_entry_t) *he;
        for (he = table->table[i]; he != NULL; he = he->next) {
            if ((!TEST(DR_HASHPERS_ONLY_IN_RANGE, flags) ||
                 HASHTABLE_NAME(,NAME_KEY,_key_in_range)(table, he, start, size)) &&
                (!TEST(DR_HASHPERS_ONLY_PERSISTED, flags) ||
                 dr_fragment_persistable(drcontext, perscxt, he->key))) {
                IF_DEBUG(count_check++;)
                if (!HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(fd, &he->key, sizeof(he->key)))
                    return false;
                if (TEST(DR_HASHPERS_PAYLOAD_IS_POINTER, flags)) {
                    if (!HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(fd, he->payload, entry_size))
                        return false;
                } else {
                    EXT_ASSERT(entry_size <= sizeof(PAYLOAD_TYPE), "inlined data too large");
                    if (!HASHTABLE_NAME(,NAME_KEY,_hash_write_file)(fd, &he->payload, entry_size))
                        return false;
                }
            }
        }
    }
    EXT_ASSERT(table->persist_count == count_check, "invalid count");
    return true;
}

/* Loads from disk and adds to table
 * Note that clone should only be false for tables that do their own payload
 * freeing and can avoid freeing a payload in the mmap.
 */
bool
HASHTABLE_NAME(,NAME_KEY,_resurrect)(void *drcontext, byte **map INOUT, HASHTABLE_TYPE *table,
                    size_t entry_size, void *perscxt, hasthable_persist_flags_t flags,
                    bool (*process_payload)(KEY_TYPE key, PAYLOAD_TYPE payload, ptr_int_t shift))
{
    uint i;
    ptr_uint_t stored_start = 0;
    ptr_int_t shift_amt = 0;
    uint count = *(uint *)(*map);
    *map += sizeof(count);
    if (TEST(DR_HASHPERS_REBASE_KEY, flags)) {
        if (perscxt == NULL)
            return false; /* invalid parameter */
        stored_start = *(ptr_uint_t *)(*map);
        *map += sizeof(stored_start);
        shift_amt = (ptr_int_t)dr_persist_start(perscxt) - (ptr_int_t)stored_start;
    }
    for (i = 0; i < count; i++) {
        PAYLOAD_TYPE inmap;
        PAYLOAD_TYPE toadd;
        KEY_TYPE key = *(KEY_TYPE*)(*map);
        *map += sizeof(key);
        inmap = (PAYLOAD_TYPE) *map;
        *map += entry_size;
        if (TEST(DR_HASHPERS_PAYLOAD_IS_POINTER, flags)) {
            toadd = inmap;
            if (TEST(DR_HASHPERS_CLONE_PAYLOAD, flags)) {
                PAYLOAD_TYPE inheap = HASHTABLE_ALLOCATOR(entry_size);
                memcpy(inheap, inmap, entry_size);
                toadd = inheap;
            }
        } else {
            toadd = NULL;
            memcpy(&toadd, inmap, entry_size);
        }
        if (TEST(DR_HASHPERS_REBASE_KEY, flags)) {
            key = (KEY_TYPE) (((ptr_int_t)key) + shift_amt);
        }
        if (process_payload != NULL) {
            if (!process_payload(key, toadd, shift_amt))
                return false;
        } else if (!HASHTABLE_NAME(,NAME_KEY,_add)(table, key, toadd))
            return false;
    }
    return true;
}
#endif

#undef NAME_KEY
#undef HASHTABLE_NAME_KEY
#undef KEY_TYPE
#undef HASHTABLE_KEY_TYPE
#undef KEY_IS_POINTER
#undef HASHTABLE_KEY_IS_POINTER
#undef PAYLOAD_TYPE
#undef HASHTABLE_PAYLOAD_TYPE
#undef HASHTABLE_PAYLOAD_IS_POINTER
#undef _IF_PAYLOAD_INLINE
#undef HASHTABLE_IS_EMPTY
#undef HASHTABLE_INIT_EMPTY
#undef HASHTABLE_EXPAND_KEY
#undef HASHTABLE_NAME
#undef HASHTABLE_TYPE
#undef CUSTOM_KEY_TYPE
#undef CUSTOM_PAYLOAD_TYPE
