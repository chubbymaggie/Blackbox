/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
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

#if defined(HASHTABLE_NAME_KEY) || !defined(_EXT_HASHTABLE_H_)
#define _EXT_HASHTABLE_H_ 1

/**
 * @file hashtable.h
 * @brief Header for DynamoRIO Hashtable Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "dr_api.h"

/***************************************************************************
 * HASHTABLE
 */

/**
 * \addtogroup drcontainers Container Data Structures
 */
/*@{*/ /* begin doxygen group */

#ifndef HASHTABLE_NAME_KEY
# define HASHTABLE_NAME_KEY hashtable
#endif
#define NAME_KEY HASHTABLE_NAME_KEY

#ifndef HASHTABLE_KEY_TYPE
# define HASHTABLE_KEY_TYPE void*
#endif
#define KEY_TYPE HASHTABLE_KEY_TYPE

#ifdef HASHTABLE_PAYLOAD_TYPE
# define CUSTOM_PAYLOAD_TYPE 1
#endif

#ifndef HASHTABLE_PAYLOAD_TYPE
# define HASHTABLE_PAYLOAD_TYPE void*
# define HASHTABLE_PAYLOAD_IS_POINTER 1
#endif
#define PAYLOAD_TYPE HASHTABLE_PAYLOAD_TYPE

#ifdef HASHTABLE_PAYLOAD_IS_POINTER
# define _IF_PAYLOAD_INLINE(x)
#else
# define _IF_PAYLOAD_INLINE(x) x
#endif

#define HASHTABLE_EXPAND_KEY(pre, key, post) pre##key##post
#define HASHTABLE_NAME(pre, name, post) HASHTABLE_EXPAND_KEY(pre, name, post)
#define HASHTABLE_TYPE HASHTABLE_NAME(,NAME_KEY,_t)

#ifndef _EXT_HASHTABLE_SHARED
#define _EXT_HASHTABLE_SHARED 1

/** The type of hash key */
typedef enum {
    HASH_INTPTR,        /**< A pointer-sized integer or pointer */
    HASH_STRING,        /**< A case-sensitive string */
    HASH_STRING_NOCASE, /**< A case-insensitive string */
    /**
     * A custom key.  Hash and compare operations must be provided
     * in hashtable_init_ex().  The hash operation can return a full
     * uint, as its result will be truncated via a mod of the
     * hash key bit size.  This allows for resizing the table
     * without changing the hash operation.
     */
    HASH_CUSTOM,
} hash_type_t;

/** Configuration parameters for a hashtable. */
typedef struct _hashtable_config_t {
    size_t size; /**< The size of the hashtable_config_t struct used */
    bool resizable; /**< Whether the table should be resized */
    uint resize_threshold; /**< Resize the table at this % full */
} hashtable_config_t;


/* DR_API EXPORT BEGIN */
/** Flags to control hashtable persistence */
typedef enum {
    /**
     * Valid for hashtable_persist() and hashtable_resurrect() and the
     * same value must be passed to both.  Treats payloads as pointers
     * to allocated memory.  By default payloads are treated as
     * inlined values if this flag is not set.
     */
    DR_HASHPERS_PAYLOAD_IS_POINTER      = 0x0001,
    /**
     * Valid for hashtable_resurrect().  Only applies if
     * DR_HASHPERS_KEY_IS_POINTER.  Performs a shallow clone of the
     * payload upon resurrection.  If this flag is not set, the
     * payloads will remain pointing into the mapped file.
     */
    DR_HASHPERS_CLONE_PAYLOAD           = 0x0002,
    /**
     * Valid for hashtable_persist_size(), hashtable_persist(), and
     * hashtable_resurrect(), and the same value must be passed to all.
     * Only applies if keys are of type HASH_INTPTR.  Adjusts each key by
     * the difference in the persist-time start address of the persisted
     * code region and the resurrected start address.  The value of this
     * flag must match across all three calls hashtable_persist_size(),
     * hashtable_persist(), and hashtable_resurrect().
     */
    DR_HASHPERS_REBASE_KEY              = 0x0004,
    /**
     * Valid for hashtable_persist_size() and hashtable_persist() and
     * the same value must be passed to both.  Only applies if keys
     * are of type HASH_INTPTR.  Only persists entries whose key is
     * in the address range being persisted.
     */
    DR_HASHPERS_ONLY_IN_RANGE           = 0x0008,
    /**
     * Valid for hashtable_persist_size() and hashtable_persist() and
     * the same value must be passed to both.  Only applies if keys
     * are of type HASH_INTPTR.  Only persists entries for which
     * dr_fragment_persistable() returns true.
     */
    DR_HASHPERS_ONLY_PERSISTED          = 0x0010,
} hasthable_persist_flags_t;
/* DR_API EXPORT END */
#endif

#ifndef HASHTABLE_PAYLOAD_IS_POINTER
# pragma pack(push, 4)
#endif

typedef struct HASHTABLE_NAME(_,NAME_KEY,_entry_t) {
    KEY_TYPE key;
    PAYLOAD_TYPE payload;
    struct HASHTABLE_NAME(_,NAME_KEY,_entry_t) *next;
} HASHTABLE_NAME(,NAME_KEY,_entry_t);

#ifndef HASHTABLE_PAYLOAD_IS_POINTER
# pragma pack(pop)
#endif

typedef struct HASHTABLE_NAME(_,NAME_KEY,_t) {
    HASHTABLE_NAME(,NAME_KEY,_entry_t) **table;
    hash_type_t hashtype;
    bool str_dup;
    void *lock;
    uint table_bits;
    bool synch;
    void (*free_payload_func)(PAYLOAD_TYPE);
    uint (*hash_key_func)(KEY_TYPE);
    bool (*cmp_key_func)(KEY_TYPE, KEY_TYPE);
    uint entries;
    hashtable_config_t config;
    uint persist_count;
} HASHTABLE_TYPE;

/* should move back to utils.c once have iterator and alloc_exit
 * doesn't need this macro
 */
#define HASHTABLE_SIZE(num_bits) (1U << (num_bits))

/** Caseless string compare */
bool
HASHTABLE_NAME(,NAME_KEY,_stri_eq)(const char *s1, const char *s2);

/**
 * The hashtable has parametrized heap and assert routines for flexibility.
 * This routine must be called BEFORE any other hashtable_ routine; else,
 * the defaults will be used.
 */
void
HASHTABLE_NAME(,NAME_KEY,_global_config)(PAYLOAD_TYPE (*alloc_func)(size_t), void (*free_func)(PAYLOAD_TYPE, size_t),
                        void (*assert_fail_func)(const char *));

/**
 * Initializes a hashtable with the given size, hash type, and whether to
 * duplicate string keys.  All operations are synchronized by default.
 */
void
HASHTABLE_NAME(,NAME_KEY,_init)(HASHTABLE_TYPE *table, uint num_bits, hash_type_t hashtype, bool str_dup);

/**
 * Initializes a hashtable with the given parameters.
 *
 * @param[out] table     The hashtable to be initialized.
 * @param[in]  num_bits  The initial number of bits to use for the hash key
 *   which determines the initial size of the table itself.  The result of the
 *   hash function will be truncated to this size.  This size will be
 *   increased when the table is resized (resizing always doubles the size).
 * @param[in]  hashtype  The type of hash to perform.
 * @param[in]  str_dup   Whether to duplicate string keys.
 * @param[in]  synch     Whether to synchronize each operation.
 *   Even when \p synch is false, the hashtable's lock is initialized and can
 *   be used via hashtable_lock() and hashtable_unlock(), allowing the caller
 *   to extend synchronization beyond just the operation in question, to
 *   include accessing a looked-up payload, e.g.
 * @param[in]  free_payload_func   A callback for freeing each payload.
 *   Leave it NULL if no callback is needed.
 * @param[in]  hash_key_func       A callback for hashing a key.
 *   Leave it NULL if no callback is needed and the default is to be used.
 *   For HASH_CUSTOM, a callback must be provided.
 *   The hash operation can return a full uint, as its result will be
 *   truncated via a mod of the hash key bit size.  This allows for resizing
 *   the table without changing the hash operation.
 * @param[in]  cmp_key_func        A callback for comparing two keys.
 *   Leave it NULL if no callback is needed and the default is to be used.
 *   For HASH_CUSTOM, a callback must be provided.
 */
void
HASHTABLE_NAME(,NAME_KEY,_init_ex)(HASHTABLE_TYPE *table, uint num_bits, hash_type_t hashtype,
                  bool str_dup, bool synch, void (*free_payload_func)(PAYLOAD_TYPE),
                  uint (*hash_key_func)(KEY_TYPE), bool (*cmp_key_func)(KEY_TYPE, KEY_TYPE));

/** Configures optional parameters of hashtable operation. */
void
HASHTABLE_NAME(,NAME_KEY,_configure)(HASHTABLE_TYPE *table, hashtable_config_t *config);

/** Returns the payload for the given key, or NULL if the key is not found */
PAYLOAD_TYPE _IF_PAYLOAD_INLINE(*)
HASHTABLE_NAME(,NAME_KEY,_lookup)(HASHTABLE_TYPE *table, KEY_TYPE key);

/* convenience version for inline entries */
#ifndef HASHTABLE_PAYLOAD_IS_POINTER
PAYLOAD_TYPE
HASHTABLE_NAME(,NAME_KEY,_lookup_value)(HASHTABLE_TYPE *table, KEY_TYPE key);
#endif

/**
 * Adds a new entry.  Returns false if an entry for \p key already exists.
 * \note Never use NULL as a payload as that is used for a lookup failure.
 */
bool
HASHTABLE_NAME(,NAME_KEY,_add)(HASHTABLE_TYPE *table, KEY_TYPE key, PAYLOAD_TYPE payload);

/**
 * Adds a new entry, replacing an existing entry if any. Returns a pointer to the removed entry
 * if there is one, unless the table has inlined payload, in which case it returns a pointer to
 * the inserted entry (either way it saves the caller a lookup to get the faraway handle).
 * \note Never use NULL (or any HASHTABLE_IS_EMPTY) as a payload as that is used for a lookup failure.
 */
PAYLOAD_TYPE _IF_PAYLOAD_INLINE(*)
HASHTABLE_NAME(,NAME_KEY,_add_replace)(HASHTABLE_TYPE *table, KEY_TYPE key, PAYLOAD_TYPE payload);

/**
 * Removes the entry for key.  If free_payload_func was specified calls it
 * for the payload being removed.  Returns false if no such entry
 * exists.
 */
bool
HASHTABLE_NAME(,NAME_KEY,_remove)(HASHTABLE_TYPE *table, KEY_TYPE key);

/**
 * Removes all entries with key in [start..end).  If free_payload_func
 * was specified calls it for each payload being removed.  Returns
 * false if no such entry exists.
 */
bool
HASHTABLE_NAME(,NAME_KEY,_remove_range)(HASHTABLE_TYPE *table, KEY_TYPE start, KEY_TYPE end);

/**
 * Removes all entries from the table.  If free_payload_func was specified
 * calls it for each payload.
 */
void
HASHTABLE_NAME(,NAME_KEY,_clear)(HASHTABLE_TYPE *table);

/**
 * Destroys all storage for the table, including all entries and the
 * table itself.  If free_payload_func was specified calls it for each
 * payload.
 */
void
HASHTABLE_NAME(,NAME_KEY,_delete)(HASHTABLE_TYPE *table);

/** Acquires the hashtable lock. */
void
HASHTABLE_NAME(,NAME_KEY,_lock)(HASHTABLE_TYPE *table);

/** Releases the hashtable lock. */
void
HASHTABLE_NAME(,NAME_KEY,_unlock)(HASHTABLE_TYPE *table);

#ifndef CUSTOM_PAYLOAD_TYPE
/**
 * For use persisting a table of single-alloc entries (i.e., via a
 * shallow copy) for loading into a live table later.
 *
 * These routines assume that the caller is synchronizing across the
 * call to hashtable_persist_size() and hashtable_persist().  If these
 * are called using DR's persistence interface, DR guarantees
 * synchronization.
 *
 * @param[in] drcontext   The opaque DR context
 * @param[in] table       The table to persist
 * @param[in] entry_size  The size of each table entry payload
 * @param[in] perscxt     The opaque persistence context from DR's persist events
 * @param[in] flags       Controls various aspects of the persistence
 */
size_t
HASHTABLE_NAME(,NAME_KEY,_persist_size)(void *drcontext, HASHTABLE_TYPE *table, size_t entry_size,
                       void *perscxt, hasthable_persist_flags_t flags);

/**
 * For use persisting a table of single-alloc entries (i.e., via a
 * shallow copy) for loading into a live table later.
 *
 * These routines assume that the caller is synchronizing across the
 * call to hashtable_persist_size() and hashtable_persist().  If these
 * are called using DR's persistence interface, DR guarantees
 * synchronization.
 *
 * hashtable_persist_size() must be called immediately prior to
 * calling hashtable_persist().
 *
 * @param[in] drcontext   The opaque DR context
 * @param[in] table       The table to persist
 * @param[in] entry_size  The size of each table entry payload
 * @param[in] fd          The target persisted file handle
 * @param[in] perscxt     The opaque persistence context from DR's persist events
 * @param[in] flags       Controls various aspects of the persistence
 */
bool
HASHTABLE_NAME(,NAME_KEY,_persist)(void *drcontext, HASHTABLE_TYPE *table, size_t entry_size,
                  file_t fd, void *perscxt, hasthable_persist_flags_t flags);

/**
 * For use persisting a table of single-alloc entries (i.e., via a
 * shallow copy) for loading into a live table later.
 *
 * Reads in entries from disk and adds them to the live table.
 *
 * @param[in] drcontext   The opaque DR context
 * @param[in] map         The mapped-in persisted file, pointing at the
 *   data written by hashtable_persist()
 * @param[in] table       The live table to add to
 * @param[in] entry_size  The size of each table entry payload
 * @param[in] perscxt     The opaque persistence context from DR's persist events
 * @param[in] flags       Controls various aspects of the persistence
 * @param[in] process_payload  If non-NULL, calls process_payload instead of
 *   hashtable_add.  process_payload can then adjust the paylod and if
 *   it wishes invoke hashtable_add.
 */
bool
HASHTABLE_NAME(,NAME_KEY,_resurrect)(void *drcontext, byte **map /*INOUT*/, HASHTABLE_TYPE *table,
                    size_t entry_size, void *perscxt, hasthable_persist_flags_t flags,
                    bool (*process_payload)(KEY_TYPE key, PAYLOAD_TYPE payload, ptr_int_t shift));
#endif

/*@}*/ /* end doxygen group */

#undef NAME_KEY
#undef HASHTABLE_NAME_KEY
#undef KEY_TYPE
#undef HASHTABLE_KEY_TYPE
#undef PAYLOAD_TYPE
#undef HASHTABLE_PAYLOAD_TYPE
#undef HASHTABLE_PAYLOAD_IS_POINTER
#undef _IF_PAYLOAD_INLINE
#undef HASHTABLE_EXPAND_KEY
#undef HASHTABLE_NAME
#undef HASHTABLE_TYPE

#ifdef __cplusplus
}
#endif

#endif /* _HASHTABLE_H_ */
