/* **********************************************************
 * Copyright (c) 2011 Google, Inc.  All rights reserved.
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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
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

/* Containers DynamoRIO Extension: DrVector */

#if defined(VECTOR_NAME_KEY) || !defined(_DRVECTOR_H_)
#define _DRVECTOR_H_ 1

/**
 * @file drvector.h
 * @brief Header for DynamoRIO DrVector Extension
 */

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************
 * DRVECTOR
 */

/* Template Variables:
 * VECTOR_ENTRY_TYPE : type
 * VECTOR_NAME_KEY : token
 * VECTOR_SORTED : bool
 */
    
/**
 * \addtogroup drcontainers Container Data Structures
 */
/*@{*/ /* begin doxygen group */

#ifndef VECTOR_NAME_KEY
#define VECTOR_NAME_KEY drvector
#endif
#define NAME_KEY VECTOR_NAME_KEY
    
#ifndef VECTOR_ENTRY_TYPE
# define VECTOR_ENTRY_TYPE void*
#endif
#define ENTRY_TYPE VECTOR_ENTRY_TYPE

#ifndef VECTOR_COMPARISON_TYPE
# define VECTOR_COMPARISON_TYPE ENTRY_TYPE
#endif
#define COMPARISON_TYPE VECTOR_COMPARISON_TYPE

#define VECTOR_EXPAND_KEY(pre, key, post) pre##key##post    
#define VECTOR_NAME(pre, name, post) VECTOR_EXPAND_KEY(pre, name, post)
#define VECTOR_TYPE VECTOR_NAME(,NAME_KEY,_t)

#ifdef VECTOR_SORTED
# define _IF_SORTED(...) __VA_ARGS__
# define _IF_NOT_SORTED(...)
#else
# define _IF_SORTED(...)
# define _IF_NOT_SORTED(...) __VA_ARGS__
#endif

#ifdef VECTOR_ENTRY_INLINE
# define _IF_ENTRY_INLINE(...) __VA_ARGS__
# define _IF_ENTRY_POINTER(...)
#else
# define _IF_ENTRY_INLINE(...)
# define _IF_ENTRY_POINTER(...) __VA_ARGS__
#endif

typedef struct VECTOR_NAME(_,NAME_KEY,_t) VECTOR_TYPE;
struct VECTOR_NAME(_,NAME_KEY,_t) {
    uint entries;
    uint capacity;
    ENTRY_TYPE *array;
    bool synch;
    bool track_memory;
    void *lock;
    void (*free_data_func)(ENTRY_TYPE);
#ifdef VECTOR_SORTED
    int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE);
#endif    
};

/**
 * Initializes a drvector with the given parameters
 *
 * @param[out] vec     The vector to be initialized.
 * @param[in]  initial_capacity  The initial number of entries allocated
     for the vector.
 * @param[in]  synch     Whether to synchronize each operation.
 *   Even when \p synch is false, the vector's lock is initialized and can
 *   be used via vector_lock() and vector_unlock(), allowing the caller
 *   to extend synchronization beyond just the operation in question, to
 *   include accessing a looked-up payload, e.g.
 * @param[in]  free_data_func   A callback for freeing each data item.
 *   Leave it NULL if no callback is needed.
 */
bool
VECTOR_NAME(,NAME_KEY,_init)(VECTOR_TYPE *vec, uint initial_capacity, bool synch, 
        void (*free_data_func)(ENTRY_TYPE) _IF_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)));


#ifdef VECTOR_SORTED
bool
VECTOR_NAME(,NAME_KEY,_insert)(VECTOR_TYPE *vec, ENTRY_TYPE data, COMPARISON_TYPE position);

_IF_ENTRY_INLINE(bool) _IF_ENTRY_POINTER(ENTRY_TYPE)
VECTOR_NAME(,NAME_KEY,_remove)(VECTOR_TYPE *vec, COMPARISON_TYPE position);
#else
/**
 * Returns the entry at index \p idx.  For an unsychronized table, the caller
 * is free to directly access the \p array field of \p vec.
 */
ENTRY_TYPE
VECTOR_NAME(,NAME_KEY,_get_entry)(VECTOR_TYPE *vec, uint idx);

bool
VECTOR_NAME(,NAME_KEY,_append)(VECTOR_TYPE *vec, ENTRY_TYPE data);

bool
VECTOR_NAME(,NAME_KEY,_sort)(VECTOR_TYPE *vec, int (*comparator)(ENTRY_TYPE, ENTRY_TYPE));

bool
VECTOR_NAME(,NAME_KEY,_remove)(VECTOR_TYPE *vec, uint index);
#endif

ENTRY_TYPE _IF_ENTRY_INLINE(*)
VECTOR_NAME(,NAME_KEY,_search)(VECTOR_TYPE *vec, COMPARISON_TYPE target 
        _IF_NOT_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)));

ENTRY_TYPE _IF_ENTRY_INLINE(*)
VECTOR_NAME(,NAME_KEY,_overlap_search)(VECTOR_TYPE *vec, COMPARISON_TYPE start, COMPARISON_TYPE end
        _IF_NOT_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)));

void
VECTOR_NAME(,NAME_KEY,_clear)(VECTOR_TYPE *vec);

/**
 * Destroys all storage for the vector.  If free_payload_func was specified
 * calls it for each payload. 
 */
bool
VECTOR_NAME(,NAME_KEY,_delete)(VECTOR_TYPE *vec);

/** Acquires the vector lock. */
void
VECTOR_NAME(,NAME_KEY,_lock)(VECTOR_TYPE *vec);

/** Releases the vector lock. */
void
VECTOR_NAME(,NAME_KEY,_unlock)(VECTOR_TYPE *vec);

/*@}*/ /* end doxygen group */

#undef NAME_KEY
#undef VECTOR_NAME_KEY
#undef ENTRY_TYPE
#undef VECTOR_ENTRY_TYPE
#undef VECTOR_EXPAND_KEY
#undef VECTOR_NAME
#undef VECTOR_TYPE
#undef VECTOR_SORTED
#undef VECTOR_ENTRY_INLINE
#undef COMPARISON_TYPE
#undef VECTOR_COMPARISON_TYPE
#undef VECTOR_ALLOWS_DUPLICATES
#undef VECTOR_UNIQUE
#undef _IF_SORTED
#undef _IF_NOT_SORTED
#undef _IF_ENTRY_INLINE
#undef _IF_ENTRY_POINTER

#ifdef __cplusplus
}
#endif

#endif /* _DRVECTOR_H_ */
