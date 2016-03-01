
#ifndef MULTIMAP_KEY_TYPE
# define MULTIMAP_KEY_TYPE void*
#endif

#ifndef MULTIMAP_VALUE_TYPE
# define MULTIMAP_VALUE_TYPE void*
#endif

#ifndef MULTIMAP_NAME_KEY
# define MULTIMAP_NAME_KEY drmultimap
#endif

#ifndef MULTIMAP_KEY_SIZE
# define MULTIMAP_KEY_SIZE 17
#endif

#define MULTIMAP_EXPAND_KEY(pre, key, post) pre##key##post
#define MULTIMAP_NAME(pre, name, post) MULTIMAP_EXPAND_KEY(pre, name, post)
#define MULTIMAP_TYPE MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_t)
#define MULTIMAP_ENTRY_TYPE MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_t)

#define MULTIMAP_HASHTABLE_NAME_KEY MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_hashtable)
#define MULTIMAP_HASHTABLE_TYPE MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_t)

#define MULTIMAP_VECTOR_NAME_KEY MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_vector)
#define MULTIMAP_VECTOR_TYPE MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_t)

#define MM_LOG(...) CS_NOLOCK_LOG("MM| "__VA_ARGS__)

/**** Private Fields ****/

// state values used in MULTIMAP_ENTRY_TYPE.singleton
#define MULTIMAP_EMPTY_VALUE 0x1
#define MULTIMAP_MANY_VALUE 0x2

// cs-todo: not really safe for general data types
#define MULTIMAP_IS_EMPTY(entry) ((uint)entry->singleton == MULTIMAP_EMPTY_VALUE)
#define MULTIMAP_IS_MANY(entry) ((uint)entry->singleton == MULTIMAP_MANY_VALUE)
#define MULTIMAP_IS_SINGLETON(entry) ((uint)entry->singleton > MULTIMAP_MANY_VALUE)
#define MULTIMAP_SET_EMPTY(entry) (entry->singleton = (MULTIMAP_VALUE_TYPE)MULTIMAP_EMPTY_VALUE)
#define MULTIMAP_SET_MANY(entry) (entry->singleton = (MULTIMAP_VALUE_TYPE)MULTIMAP_MANY_VALUE)

/**** Private Prototypes ****/

static MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_get_empty_entry)(MULTIMAP_TYPE *multimap);

/**** Public Functions ****/

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_init)(MULTIMAP_TYPE *multimap, void (*notify_value_removed)(MULTIMAP_VALUE_TYPE), char *name) {
    multimap->table = (MULTIMAP_HASHTABLE_TYPE*)CS_ALLOC(sizeof(MULTIMAP_HASHTABLE_TYPE));
    MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_init_ex)(
        multimap->table,
        MULTIMAP_KEY_SIZE,
        HASH_INTPTR, /* could parameterize */
        false,
        false,
        NULL, /* cleanup if ever collapsing the pool */
        NULL, /* no custom hashing */
        NULL);

    // no "free" function: entries remain valid (pooled) after removal
    multimap->entry_pool = (drvector_t*)CS_ALLOC(sizeof(drvector_t));
    drvector_init(multimap->entry_pool, 1024, false, NULL);

    multimap->notify_value_removed = notify_value_removed;

    multimap->item_count = 0;
    multimap->largest_entry = 0;
    multimap->name = name;
}

MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_entry_add_item)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key,
    MULTIMAP_ENTRY_TYPE *entry, MULTIMAP_VALUE_TYPE value)
{
    //ASSERT_TAG_XREF_LOCK;
    ASSERT(p2int(value) > MULTIMAP_MANY_VALUE);

    if (entry == NULL) {
        entry = MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_get_empty_entry)(multimap);
        MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_add)(multimap->table, key, entry);
        entry->singleton = value;
    } else if (MULTIMAP_IS_EMPTY(entry)) {
        entry->singleton = value;
    } else {
        if (MULTIMAP_IS_SINGLETON(entry)) {
            if (entry->vector == NULL) {
                entry->vector = (MULTIMAP_VECTOR_TYPE *)CS_ALLOC(sizeof(MULTIMAP_VECTOR_TYPE));
                MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_init)(entry->vector, 4, false, NULL);
            }
            MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_append)(entry->vector, entry->singleton);
            MULTIMAP_SET_MANY(entry);
        }
        MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_append)(entry->vector, value);
    }

    multimap->item_count++;
    if ((!MULTIMAP_IS_SINGLETON(entry)) && (entry->vector->entries > multimap->largest_entry))
        multimap->largest_entry = entry->vector->entries;
    if ((multimap->item_count & 0xffff) == 0)
        CS_DET("Multimap '%s' has %d items in %d entries. Largest entry has %d items.\n", multimap->name,
            multimap->item_count, multimap->table->entries, multimap->largest_entry);

    return entry;
}

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_entry)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key) {
    //ASSERT_TAG_XREF_LOCK;

    MULTIMAP_ENTRY_TYPE *entry = MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_lookup)(multimap->table, key);
    if (entry != NULL) {
        if (multimap->notify_value_removed != NULL) {
            if (MULTIMAP_IS_SINGLETON(entry)) {
                multimap->item_count--;
                multimap->notify_value_removed(entry->singleton);
            } else if (MULTIMAP_IS_MANY(entry)) {
                uint i;
                for (i = 0; i < entry->vector->entries; i++) {
                    multimap->notify_value_removed(entry->vector->array[i]);
                }
                multimap->item_count -= entry->vector->entries;
                MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_clear)(entry->vector);
            }
        } else if (MULTIMAP_IS_MANY(entry)) {
            multimap->item_count -= entry->vector->entries;
            MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_clear)(entry->vector);
        } else {
            multimap->item_count--;
        }

        MULTIMAP_SET_EMPTY(entry);
        drvector_append(multimap->entry_pool, entry);
        MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_remove)(multimap->table, key);
    }
}

bool
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_value)(MULTIMAP_TYPE *multimap, MULTIMAP_KEY_TYPE key, MULTIMAP_VALUE_TYPE value) {
    MULTIMAP_ENTRY_TYPE *entry = MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_lookup)(multimap->table, key);
    if (entry != NULL) {
        if (MULTIMAP_IS_SINGLETON(entry)) {
            MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_entry)(multimap, key);
            return true;
        } else if (MULTIMAP_IS_MANY(entry)) {
            uint i;
            for (i = 0; i < entry->vector->entries; i++) {
                if (entry->vector->array[i] == value) { // what about inline types? and sorted vectors?
                    MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_remove)(entry->vector, i);
                    multimap->item_count--;
                    if (entry->vector->entries == 0)
                        MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_remove_entry)(multimap, key);
                    return true;
                }
            }
        }
    }
    return false;
}

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_clear)(MULTIMAP_TYPE *multimap) {
    uint i;
    for (i = 0; i < HASHTABLE_SIZE(multimap->table->table_bits); i++) {
        MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_entry_t) *e = multimap->table->table[i];
        while (e != NULL) {
            MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_entry_t) *nexte = e->next;
            MULTIMAP_ENTRY_TYPE *entry = e->payload;
            if ((multimap->notify_value_removed != NULL) && MULTIMAP_IS_MANY(entry)) {
                uint j;
                for (j = 0; j <  entry->vector->entries; j++)
                    multimap->notify_value_removed(entry->vector->array[j]);
            }
            MULTIMAP_SET_EMPTY(entry);
            drvector_append(multimap->entry_pool, entry);
            MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_hash_free)(e, sizeof(*e));
            e = nexte;
        }
        multimap->table->table[i] = NULL;
    }
    multimap->table->entries = 0;
}

void
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_delete)(MULTIMAP_TYPE *multimap) {
    uint i;
    MULTIMAP_ENTRY_TYPE *entry;

    // clear the hashtable, to push all entries into the pool, and notify the client
    // to delete the payloads
    MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_clear)(multimap);

    // free the hashtable (will not free the payloads, i.e. multimap entries)
    MULTIMAP_NAME(,MULTIMAP_HASHTABLE_NAME_KEY,_delete)(multimap->table);
    dr_global_free(multimap->table, sizeof(MULTIMAP_HASHTABLE_TYPE));

    // delete all the entry vectors (payloads are gone already, per `clear` above)
    for (i = 0; i < multimap->entry_pool->entries; i++) {
        entry = multimap->entry_pool->array[i];
        if (entry->vector != NULL) {
            MULTIMAP_NAME(,MULTIMAP_VECTOR_NAME_KEY,_delete)(entry->vector);
            dr_global_free(entry->vector, sizeof(MULTIMAP_VECTOR_TYPE));
        }
        dr_global_free(entry, sizeof(MULTIMAP_ENTRY_TYPE));
    }

    // delete the pool
    drvector_delete(multimap->entry_pool);
    dr_global_free(multimap->entry_pool, sizeof(drvector_t));
}

/**** Private Functions ****/

static inline MULTIMAP_ENTRY_TYPE *
MULTIMAP_NAME(,MULTIMAP_NAME_KEY,_get_empty_entry)(MULTIMAP_TYPE *multimap) {
    MULTIMAP_ENTRY_TYPE* entry;
    //ASSERT_TAG_XREF_LOCK;

    if (multimap->entry_pool->entries > 0) {
        entry = drvector_get_entry(multimap->entry_pool, multimap->entry_pool->entries-1);
        drvector_remove(multimap->entry_pool, multimap->entry_pool->entries-1);
    } else {
        entry = (MULTIMAP_ENTRY_TYPE*)CS_ALLOC(sizeof(MULTIMAP_ENTRY_TYPE));
        entry->vector = NULL;
        MULTIMAP_SET_EMPTY(entry);
    }

    //MM_LOG("%s: Pool now has %d entries\n", __FUNCTION__, multimap->entry_pool->entries);

    return entry;
}

#undef NAME_KEY
#undef KEY_TYPE
#undef MULTIMAP_KEY_TYPE
#undef VALUE_TYPE
#undef MULTIMAP_VALUE_TYPE
#undef MULTIMAP_NAME
#undef MULTIMAP_NAME_KEY
#undef MULTIMAP_TYPE
#undef MULTIMAP_ENTRY_TYPE
#undef MULTIMAP_VECTOR_ENTRY_INLINE
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
#undef MULTIMAP_SET_EMPTY
#undef MULTIMAP_SET_MANY
#undef MULTIMAP_KEY_SIZE
#undef MULTIMAP_EXPAND_KEY
#undef MM_LOG
