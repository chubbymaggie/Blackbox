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

/* Containers DynamoRIO Extension: DrVector */

/* Template Variables:
 * VECTOR_ENTRY_TYPE : type
 * VECTOR_NAME_KEY : token
 * VECTOR_SORTED : bool
 * VECTOR_COMPARISON_TYPE : type // required if VECTOR_SORTED
 */

// cs-todo: the comparator could actually be inlined via macro parameter

#include <string.h> /* memcpy */

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

#ifndef VECTOR_ALLOWS_DUPLICATES
# define VECTOR_UNIQUE 1
#endif

#ifndef VECTOR_ALLOCATOR
 #define VECTOR_ALLOCATOR dr_global_alloc
#endif
#ifndef VECTOR_DEALLOCATOR
 #define VECTOR_DEALLOCATOR dr_global_free
#endif

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

#define VERIFY_SORT 1

/**** Private Functions ****/

#ifndef VECTOR_SORTED
static bool
VECTOR_NAME(,NAME_KEY,_quicksort)(VECTOR_TYPE *vec, int (*comparator)(ENTRY_TYPE, ENTRY_TYPE),
    uint start, uint end);
#endif

static void
VECTOR_NAME(,NAME_KEY,_ensure_capacity)(VECTOR_TYPE *vec) {
    if (vec->entries >= vec->capacity) {
        uint newcap = vec->capacity * 2;
        ENTRY_TYPE *newarray = VECTOR_ALLOCATOR(newcap * sizeof(ENTRY_TYPE));
        memcpy(newarray, vec->array, vec->entries * sizeof(ENTRY_TYPE));
        VECTOR_DEALLOCATOR(vec->array, vec->capacity * sizeof(ENTRY_TYPE));
        vec->array = newarray;
        vec->capacity = newcap;
    }
}

static inline int
VECTOR_NAME(,NAME_KEY,_find_position)(VECTOR_TYPE *vec, COMPARISON_TYPE target,
        int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)) {
    uint i, start, end, span, split;
    int comparison;

    if (vec->entries == 0)
        return -1;

    start = 0;
    end = vec->entries;
    while (true) {
        span = (end - start);
        if (span < 3) {
            comparison = comparator(vec->array[start], target);
#ifdef VECTOR_UNIQUE
            if (comparison == 0)
                return start;
#else
            if (comparison == 0) { // walk back to the first match
                for (i = start; i > 0; i--) {
                    if (comparator(vec->array[i-1], target) != 0)
                        return i;
                }
                return 0;
            }
#endif
            if (comparison > 0) {
                i = start;
                break;
            }
            for (i = start + 1; i < end; i++) {
                comparison = comparator(vec->array[i], target);
                if (comparison == 0)
                    return i;
                if (comparison > 0)
                    break;
            }
            break;
        }
        split = start + (span / 2);
        comparison = comparator(vec->array[split], target);
        if (comparison < 0) {
            start = split+1;
        } else if (comparison > 0) {
            end = split;
        } else {
#ifdef VECTOR_UNIQUE
            return split;
#else
            for (i = split; i > 0; i--) { // walk back to the first match
                if (comparator(vec->array[i-1], target) != 0)
                    return i;
            }
            return 0;
#endif
        }
    }

    return -((int)i+1);
}

/**** Public Functions ****/

bool
VECTOR_NAME(,NAME_KEY,_init)(VECTOR_TYPE *vec, uint initial_capacity, bool synch,
        void (*free_data_func)(ENTRY_TYPE) _IF_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)))
{
    if (vec == NULL)
        return false;
    vec->array = VECTOR_ALLOCATOR(initial_capacity * sizeof(ENTRY_TYPE));
    vec->entries = 0;
    vec->capacity = initial_capacity;
    vec->synch = synch;
    vec->lock = dr_mutex_create();
    vec->free_data_func = free_data_func;
#ifdef VECTOR_SORTED
    vec->comparator = comparator;
#endif
    return true;
}

#ifdef VECTOR_SORTED
bool
VECTOR_NAME(,NAME_KEY,_insert)(VECTOR_TYPE *vec, ENTRY_TYPE data, COMPARISON_TYPE position) {
    int i, j;
    bool replace = true;
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);

    VECTOR_NAME(,NAME_KEY,_ensure_capacity)(vec);

    i = VECTOR_NAME(,NAME_KEY,_find_position)(vec, position, vec->comparator);
    if (i < 0) {
        replace = false;
        i = -(i+1);
        for (j = vec->entries; j > i; j--)
            vec->array[j] = vec->array[j-1];

        vec->entries++;
    }
    vec->array[i] = data;

    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return replace;
}

_IF_ENTRY_INLINE(bool) _IF_ENTRY_POINTER(ENTRY_TYPE)
VECTOR_NAME(,NAME_KEY,_remove)(VECTOR_TYPE *vec, COMPARISON_TYPE position) {
    _IF_ENTRY_POINTER(ENTRY_TYPE found;)
    int index;
    uint i;
    if (vec == NULL)
        return _IF_ENTRY_INLINE(false) _IF_ENTRY_POINTER(NULL);
    if (vec->synch)
        dr_mutex_lock(vec->lock);

    index = VECTOR_NAME(,NAME_KEY,_find_position)(vec, position, vec->comparator);
    if (index < 0)
        return _IF_ENTRY_INLINE(false) _IF_ENTRY_POINTER(NULL);

    _IF_ENTRY_POINTER(found = vec->array[index];)
    if (vec->free_data_func != NULL)
        (vec->free_data_func)(vec->array[index]);
    for (i = index; i < (vec->entries-1); i++) {
        vec->array[i] = vec->array[i+1];
    }
    vec->entries--;
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return _IF_ENTRY_INLINE(true) _IF_ENTRY_POINTER(found);
}
#else
ENTRY_TYPE
VECTOR_NAME(,NAME_KEY,_get_entry)(VECTOR_TYPE *vec, uint index)
{
    ENTRY_TYPE res = _IF_ENTRY_INLINE(0) _IF_ENTRY_POINTER(NULL);
    if (vec == NULL)
        return _IF_ENTRY_INLINE(0) _IF_ENTRY_POINTER(NULL);
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    if (index < vec->entries)
        res = vec->array[index];
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return res;
}

bool
VECTOR_NAME(,NAME_KEY,_append)(VECTOR_TYPE *vec, ENTRY_TYPE data)
{
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);

    VECTOR_NAME(,NAME_KEY,_ensure_capacity)(vec);

    vec->array[vec->entries] = data;
    vec->entries++;
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return true;
}

bool
VECTOR_NAME(,NAME_KEY,_sort)(VECTOR_TYPE *vec, int (*comparator)(ENTRY_TYPE, ENTRY_TYPE)) {
    uint i;
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    VECTOR_NAME(,NAME_KEY,_quicksort)(vec, comparator, 0, vec->entries);
# ifdef VERIFY_SORT
    for (i = 0; i < (vec->entries-1); i++) {
        DR_ASSERT(comparator(vec->array[i], vec->array[i+1]) <= 0);
    }
# endif
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return true;
}

bool
VECTOR_NAME(,NAME_KEY,_remove)(VECTOR_TYPE *vec, uint index) {
    uint i;
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    if (vec->free_data_func != NULL)
        (vec->free_data_func)(vec->array[index]);
    for (i = index; i < (vec->entries-1); i++) {
        vec->array[i] = vec->array[i+1];
    }
    vec->entries--;
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return true;
}
#endif

ENTRY_TYPE _IF_ENTRY_INLINE(*)
VECTOR_NAME(,NAME_KEY,_search)(VECTOR_TYPE *vec, COMPARISON_TYPE target
        _IF_NOT_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)))
{
    int i;
    ENTRY_TYPE _IF_ENTRY_INLINE(*)item;
    if (vec == NULL)
        return NULL;
    if (vec->synch)
        dr_mutex_lock(vec->lock);

    i = VECTOR_NAME(,NAME_KEY,_find_position)(vec, target, _IF_SORTED(vec->)comparator);
    if (i < 0)
        item = NULL;
    else
        item = _IF_ENTRY_INLINE(&)vec->array[i];

    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return item;
}

ENTRY_TYPE _IF_ENTRY_INLINE(*)
VECTOR_NAME(,NAME_KEY,_overlap_search)(VECTOR_TYPE *vec, COMPARISON_TYPE start, COMPARISON_TYPE end
        _IF_NOT_SORTED(, int (*comparator)(ENTRY_TYPE, COMPARISON_TYPE)))
{
    ENTRY_TYPE _IF_ENTRY_INLINE(*)next;
    uint index;
    int i = VECTOR_NAME(,NAME_KEY,_find_position)(vec, start, _IF_SORTED(vec->)comparator);
    if (i >= 0)
        return _IF_ENTRY_INLINE(&)vec->array[i];

    index = (uint)(-(i+1));
    next = _IF_ENTRY_INLINE(&)vec->array[index];
    if ((index < vec->entries) && (_IF_SORTED(vec->)comparator(_IF_ENTRY_INLINE(*)next, end) <= 0))
        return next;
    else
        return NULL;
}

void
VECTOR_NAME(,NAME_KEY,_clear)(VECTOR_TYPE *vec) {
    if (vec == NULL)
        return;
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    if (vec->free_data_func != NULL) {
        uint i;
        for (i = 0; i < vec->entries; i++) {
            (vec->free_data_func)(vec->array[i]);
        }
    }
    vec->entries = 0;
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
}

bool
VECTOR_NAME(,NAME_KEY,_delete)(VECTOR_TYPE *vec)
{
    uint i;
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    for (i = 0; i < vec->entries; i++) {
        if (vec->free_data_func != NULL)
            (vec->free_data_func)(vec->array[i]);
    }
    VECTOR_DEALLOCATOR(vec->array, vec->capacity * sizeof(ENTRY_TYPE));
    vec->array = NULL;
    vec->entries = 0;
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    dr_mutex_destroy(vec->lock);
    return true;
}

void
VECTOR_NAME(,NAME_KEY,_lock)(VECTOR_TYPE *vec)
{
    dr_mutex_lock(vec->lock);
}

void
VECTOR_NAME(,NAME_KEY,_unlock)(VECTOR_TYPE *vec)
{
    dr_mutex_unlock(vec->lock);
}

#ifndef VECTOR_SORTED
static bool
VECTOR_NAME(,NAME_KEY,_quicksort)(VECTOR_TYPE *vec, int (*comparator)(ENTRY_TYPE, ENTRY_TYPE), uint start, uint end) {
    uint i, j, span, split, pivot_index;
    ENTRY_TYPE swap;
    ENTRY_TYPE pivot;
    ENTRY_TYPE insert;
    if (vec == NULL)
        return false;
    if (vec->synch)
        dr_mutex_lock(vec->lock);
    span = (end - start);
    if (span > 8) {
        pivot_index = start + (span / 2);
        pivot = vec->array[pivot_index];
        vec->array[pivot_index] = vec->array[end-1];
        split = start;
        for (i = start; i < (end-1); i++) {
            swap = vec->array[i];
            if (comparator(swap, pivot) < 0) {
                if (i > split) {
                    vec->array[i] = vec->array[split];
                    vec->array[split] = swap;
                }
                split++;
            }
        }
# ifdef VERIFY_SORT
        DR_ASSERT((split == (end-1)) || comparator(pivot, vec->array[split]) <= 0);
        DR_ASSERT((split >= (end-2)) || (comparator(pivot, vec->array[split+1]) <= 0));
        DR_ASSERT((split == start) || (comparator(vec->array[split-1], pivot) <= 0));
# endif
        vec->array[end-1] = vec->array[split];
        vec->array[split] = pivot;
        VECTOR_NAME(,NAME_KEY,_quicksort)(vec, comparator, start, split);
        VECTOR_NAME(,NAME_KEY,_quicksort)(vec, comparator, split, end);
    } else {
        for (i = start+1; i < end; i++) {
            insert = vec->array[i];
            j = i-1;
            if (comparator(insert, vec->array[j]) < 0) {
                do {
                    vec->array[j+1] = vec->array[j];
                    j--;
                } while ((j >= start) && (comparator(insert, vec->array[j]) < 0));
                vec->array[j+1] = insert;
            }
        }
# ifdef VERIFY_SORT
        for (i = start; i < (end-1); i++) {
            DR_ASSERT(comparator(vec->array[i], vec->array[i+1]) <= 0);
        }
# endif
    }
    if (vec->synch)
        dr_mutex_unlock(vec->lock);
    return true;
}
#endif

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
#undef VECTOR_ALLOCATOR
#undef _IF_SORTED
#undef _IF_NOT_SORTED
#undef _IF_ENTRY_INLINE
#undef _IF_ENTRY_POINTER
