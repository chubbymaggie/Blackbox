
#if defined(MULTIMAP_NAME_KEY) || !defined(_DRMULTIMAP_H_)
#define _DRMULTIMAP_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#define PRAGMA_VALUE_TO_STRING(x) #x
#define PRAGMA_VALUE(x) PRAGMA_VALUE_TO_STRING(x)
#define PRAGMA_VAR_NAME_VALUE(var) #var "=" PRAGMA_VALUE(var)

#ifndef MULTIMAP_KEY_TYPE
# define MULTIMAP_KEY_TYPE void*
#endif

#ifndef MULTIMAP_VALUE_TYPE
# define MULTIMAP_VALUE_TYPE void*
#endif

#ifndef MULTIMAP_NAME_KEY
# define MULTIMAP_NAME_KEY drmultimap
#endif

#define MULTIMAP_EXPAND_KEY(pre, key, post) pre##key##post    
#define MULTIMAP_NAME(pre, name, post) MULTIMAP_EXPAND_KEY(pre, name, post)
#define MULTIMAP_TYPE MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_t)
#define MULTIMAP_ENTRY_TYPE MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_t)

/**** Private Fields ****/

// state values used in MULTIMAP_ENTRY_TYPE.singleton
#define MULTIMAP_EMPTY_VALUE 0x1
#define MULTIMAP_MANY_VALUE 0x2

#define MULTIMAP_IS_EMPTY(entry) ((uint)entry->singleton == MULTIMAP_EMPTY_VALUE)
#define MULTIMAP_IS_MANY(entry) ((uint)entry->singleton == MULTIMAP_MANY_VALUE)
#define MULTIMAP_IS_SINGLETON(entry) ((uint)entry->singleton > MULTIMAP_MANY_VALUE)

/**** Multimap Entry Type ****/

  /**** Vector Template ****/

#define MULTIMAP_VECTOR_NAME_KEY MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_vector)
#define MULTIMAP_VECTOR_TYPE MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_t)

#define VECTOR_NAME_KEY MULTIMAP_VECTOR_NAME_KEY
#define VECTOR_ENTRY_TYPE MULTIMAP_VALUE_TYPE
#ifdef MULTIMAP_ENTRY_INLINE
# define VECTOR_ENTRY_INLINE 1
#else
# undef VECTOR_ENTRY_INLINE
#endif
#include "../drcontainers/drvector.h"

#define VECTOR_NAME_KEY MULTIMAP_VECTOR_NAME_KEY
#define VECTOR_ENTRY_TYPE MULTIMAP_VALUE_TYPE
#ifdef MULTIMAP_ENTRY_INLINE
# define VECTOR_ENTRY_INLINE 1
#else
# undef VECTOR_ENTRY_INLINE
#endif
#include "../drcontainers/drvectorx.h"

typedef struct MULTIMAP_NAME(_,MULTIMAP_NAME_KEY,_entry_t) MULTIMAP_ENTRY_TYPE;
struct MULTIMAP_NAME(_,MULTIMAP_NAME_KEY,_entry_t) {
    MULTIMAP_VALUE_TYPE singleton;
    MULTIMAP_VECTOR_TYPE *vector;
};

/**** Multimap ****/

  /**** Hashtable Template ****/

#define MULTIMAP_HASHTABLE_NAME_KEY MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_hashtable)
#define MULTIMAP_HASHTABLE_TYPE MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_t)

#define HASHTABLE_NAME_KEY MULTIMAP_HASHTABLE_NAME_KEY
#define HASHTABLE_KEY_TYPE MULTIMAP_KEY_TYPE
#define HASHTABLE_PAYLOAD_TYPE MULTIMAP_ENTRY_TYPE*
#define HASHTABLE_PAYLOAD_IS_POINTER 1
#include "../drcontainers/drhashtable.h"

#define HASHTABLE_NAME_KEY MULTIMAP_HASHTABLE_NAME_KEY
#define HASHTABLE_KEY_TYPE MULTIMAP_KEY_TYPE
#define HASHTABLE_PAYLOAD_TYPE MULTIMAP_ENTRY_TYPE*
#define HASHTABLE_PAYLOAD_IS_POINTER 1
#include "../drcontainers/drhashtablex.h"

typedef struct MULTIMAP_NAME(_,MULTIMAP_NAME_KEY,_t) MULTIMAP_TYPE;
struct MULTIMAP_NAME(_,MULTIMAP_NAME_KEY,_t) {
    MULTIMAP_HASHTABLE_TYPE *table;
    drvector_t *entry_pool;
    void (*notify_value_removed)(MULTIMAP_VALUE_TYPE);
    uint item_count;
    uint largest_entry;
    char *name;
};

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_init)(MULTIMAP_TYPE *map, void (*notify_value_removed)(MULTIMAP_VALUE_TYPE), char *name);

MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_add_item)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key,
    MULTIMAP_ENTRY_TYPE *entry, MULTIMAP_VALUE_TYPE value);

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_entry)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key);

bool
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_value)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key, MULTIMAP_VALUE_TYPE value);

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_clear)(MULTIMAP_TYPE *multimap);

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_delete)(MULTIMAP_TYPE *multimap);

inline MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_lookup)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key) {
    return MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_lookup)(multimap->table, key);
}

inline uint
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_item_count)(MULTIMAP_ENTRY_TYPE *entry) {
    if ((entry == NULL) || MULTIMAP_IS_EMPTY(entry))
        return 0;
    if (MULTIMAP_IS_SINGLETON(entry)) 
        return 1;
    ASSERT(MULTIMAP_IS_MANY(entry));
    return entry->vector->entries;
}

inline MULTIMAP_VALUE_TYPE
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_get_item)(MULTIMAP_ENTRY_TYPE *entry, uint index) {
    ASSERT(entry != NULL);
    if (MULTIMAP_IS_SINGLETON(entry)) {
        ASSERT(index == 0);
        return entry->singleton;
    }
    ASSERT(MULTIMAP_IS_MANY(entry));
    return entry->vector->array[index];
}

inline MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_add)(MULTIMAP_TYPE *multimap, 
    MULTIMAP_KEY_TYPE key, MULTIMAP_VALUE_TYPE value)
{
    MULTIMAP_ENTRY_TYPE *entry = MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_lookup)(multimap->table, key);
    return MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_add_item)(multimap, key, entry, value);
}

#undef NAME_KEY
#undef KEY_TYPE
#undef MULTIMAP_KEY_TYPE
#undef VALUE_TYPE
#undef MULTIMAP_VALUE_TYPE
#undef ENTRY_INLINE
#undef MULTIMAP_ENTRY_INLINE
#undef MULTIMAP_ENTRY_TYPE
#undef MULTIMAP_NAME
#undef MULTIMAP_NAME_KEY
#undef MULTIMAP_TYPE
#undef MULTIMAP_VECTOR_NAME_KEY
#undef MULTIMAP_VECTOR_SORTED
#undef MULTIMAP_VECTOR_TYPE
#undef MULTIMAP_HASHTABLE_NAME_KEY
#undef MULTIMAP_HASHTABLE_TYPE
#undef MULTIMAP_EMPTY_VALUE
#undef MULTIMAP_MANY_VALUE
#undef MULTIMAP_IS_EMPTY
#undef MULTIMAP_IS_MANY
#undef MULTIMAP_IS_SINGLETON
#undef MULTIMAP_EXPAND_KEY

#ifdef __cplusplus
}
#endif

#endif
