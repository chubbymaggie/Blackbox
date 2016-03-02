//#include "../../core/globals.h"
#include "drhashtable.h"
#include "crowd_safe_util.h"
#include "module_observer.h"
#include "execution_monitor.h"
#include "blacklist.h"

/*
 *             <action> ::= <action-type> <action-type-filter>
 *        <action-type> ::= "load-module" | "node" | "edge"
 * <load-module-filter> ::= <module>
 *        <node-filter> ::= <module> <node> | "<export>" "(export-id)"
 *        <edge-filter> ::= <node-filter> <node-filter>
 *             <module> ::= "(module-name)" | "*"
 *               <node> ::= "<abnormal-return>" | "<dynamic-standalone>" |
 *                          "<dynamic-unbounded>" | "(offset)" | "*"
 */

#define BLACKLIST_ACTION_LOAD_MODULE "load-module"
#define BLACKLIST_ACTION_NODE "node"
#define BLACKLIST_ACTION_EDGE "edge"
#define BLACKLIST_EXPORT "<export>"
#define BLACKLIST_WILDCARD "*"
#define BLACKLIST_ABNORMAL_RETURN "<abnormal-return>"
#define BLACKLIST_WHITE_BOX "<dynamic-standalone>"
#define BLACKLIST_BLACK_BOX "<dynamic-unbounded>"
#define BLACKLIST_MODULE_SYSTEM "<system-call>"
#define BLACKLIST_MODULE_FORK "<process-fork>"

#define EDGE_HASH_NODE_WILDCARD 0x5555555555555555ULL
/* N.B.: not used when the other side is an export */
#define EDGE_HASH_FROM_WILDCARD 0x9999999999999999ULL
/* N.B.: not used when the other side is an export */
#define EDGE_HASH_TO_WILDCARD 0xaaaaaaaaaaaaaaaaULL
#define EDGE_HASH_BOTH_WILDCARD 0xccccccccccccccccULL

typedef enum _blacklist_node_type_offset_t {
	BLACKLIST_NODE_OFFSET_NONE,
	BLACKLIST_NODE_OFFSET_WILDCARD,
	BLACKLIST_NODE_OFFSET_ABNORMAL_RETURN,
	BLACKLIST_NODE_OFFSET_WHITE_BOX,
	BLACKLIST_NODE_OFFSET_BLACK_BOX,
} blacklist_node_type_offset_t;

typedef enum _blacklist_compare_flags_t {
    BLACKLIST_FLAG_NODE = 0x01,
    BLACKLIST_FLAG_FROM_HASH = 0x02,
    BLACKLIST_FLAG_TO_HASH = 0x04,
    BLACKLIST_FLAG_FROM_MODULE_WILDCARD = 0x08,
    BLACKLIST_FLAG_TO_MODULE_WILDCARD = 0x10,
} blacklist_compare_flags_t;

typedef struct _blacklist_node_t {
    char *module_name;
    union {
        uint offset;
        bb_hash_t edge_hash;
    };
} blacklist_node_t;

typedef struct _pending_blacklist_entry_t {
    blacklist_compare_flags_t flags;
    blacklist_node_t from;
    blacklist_node_t to;
    bb_hash_t edge_hash;
} pending_blacklist_entry_t;

typedef struct _blacklist_entry_t {
    blacklist_compare_flags_t flags;
    app_pc from;
    app_pc to;
    bb_hash_t edge_hash;
} blacklist_entry_t;

typedef struct _blacklist_node_type_t {
    blacklist_node_t from;
    blacklist_node_t to;
} blacklist_node_type_t;

#define BLACKLIST_FILENAME "blacklist.cfg"
#define PENDING_BLACKLIST_TABLE_KEY_SIZE 5
#define BLACKLIST_TABLE_KEY_SIZE 7

static inline bool
read_first_word(char **dst, char *buffer, char **mark, const char *field_name) {
    *dst = strtok_r(buffer, " ", mark);
    if (*dst == NULL) {
        CS_ERR("BL| Invalid blacklist format: failed to read the %s.\n", field_name);
        return false;
    } else {
        return true;
    }
}

static inline bool
read_next_word(char **dst, char **word_mark, const char *field_name) {
    *dst = strtok_r(NULL, " ", word_mark);
    if (*dst == NULL) {
        CS_ERR("BL| Invalid blacklist format: failed to read the %s.\n", field_name);
        return false;
    } else {
        return true;
    }
}

/****** public fields *******/

bool blacklist_enabled = false;

/****** private fields *******/

static hashtable_t *pending_blacklist_edge_table;
static hashtable_t *blacklist_edge_table;

static drvector_t *blacklist_module_load_list;
static bool blacklist_module_load_any = false;

static bool has_offset_wildcard = false;

static drvector_t *blacklist_node_type_list;

static drvector_t *establish_module_entries(const char *module_name);

static uint hash_blacklist_entry(void *e);

static bool compare_blacklist_entry(void *a, void *b);

static void free_pending_blacklist_entry(void *e);

static void free_pending_blacklist_module_entries(void *e);

static void free_blacklist_entry(void *e);

static void free_module_load_entry(void *e);

static void free_blacklist_node_type(void *e);

/****** public functions *******/

static bool
load_module_entry(char **word_mark) {
    char *module_name, *module_entry;

    if (!read_next_word(&module_name, word_mark, "module specifier"))
        return false;

    if (strcmp(module_name, BLACKLIST_WILDCARD) == 0) {
        blacklist_module_load_any = true;
    } else {
        module_entry = cs_strcpy(module_name);
        drvector_append(blacklist_module_load_list, module_entry);
    }
    return true;
}

static blacklist_node_type_offset_t
map_node_type_to_offset(char *offset_str) {
	if (strcmp(offset_str, BLACKLIST_WILDCARD) == 0)
		return BLACKLIST_NODE_OFFSET_WILDCARD;
	if (strcmp(offset_str, BLACKLIST_ABNORMAL_RETURN) == 0)
		return BLACKLIST_NODE_OFFSET_ABNORMAL_RETURN;
	if (strcmp(offset_str, BLACKLIST_WHITE_BOX) == 0)
		return BLACKLIST_NODE_OFFSET_WHITE_BOX;
	if (strcmp(offset_str, BLACKLIST_BLACK_BOX) == 0)
		return BLACKLIST_NODE_OFFSET_BLACK_BOX;
	return BLACKLIST_NODE_OFFSET_NONE;
}

static const char *
map_node_type_offset_to_entry_text(uint offset) {
	if (offset == BLACKLIST_NODE_OFFSET_WILDCARD)
		return BLACKLIST_WILDCARD;
    if (offset == BLACKLIST_NODE_OFFSET_ABNORMAL_RETURN)
		return BLACKLIST_ABNORMAL_RETURN;
    if (offset == BLACKLIST_NODE_OFFSET_WHITE_BOX)
		return BLACKLIST_WHITE_BOX;
    if (offset == BLACKLIST_NODE_OFFSET_BLACK_BOX)
		return BLACKLIST_BLACK_BOX;

	return NULL;
}

static inline bool
is_node_type(module_location_t *module, bb_state_t *state) {
	return IS_BB_UNEXPECTED_RETURN(state) ||
	       IS_BB_WHITE_BOX(module, state) ||
		   IS_BB_BLACK_BOX(state);
}

static bool
load_edge_entry(char **word_mark) {
    char *from_module, *to_module, *from_offset_str, *to_offset_str;
    pending_blacklist_entry_t *entry = NULL;
    drvector_t *module_entries;
    bool from_wildcard, to_wildcard, from_export, to_export;
	blacklist_node_type_offset_t from_node_type_offset, to_node_type_offset;

    if (!read_next_word(&from_module, word_mark, "from module specifier"))
        return false;
    if (!read_next_word(&from_offset_str, word_mark, "from node specifier"))
        return false;
    if (!read_next_word(&to_module, word_mark, "to module specifier"))
        return false;
    if (!read_next_word(&to_offset_str, word_mark, "to node specifier"))
        return false;

    from_export = (strcmp(from_module, BLACKLIST_EXPORT) == 0);
    to_export = (strcmp(to_module, BLACKLIST_EXPORT) == 0);
	from_node_type_offset = map_node_type_to_offset(from_offset_str);
	to_node_type_offset = map_node_type_to_offset(to_offset_str);

    if (from_node_type_offset > BLACKLIST_NODE_OFFSET_NONE || to_node_type_offset > BLACKLIST_NODE_OFFSET_NONE) {
        blacklist_node_type_t *node = CS_ALLOC(sizeof(blacklist_node_type_t));
        node->from.module_name = cs_strcpy(from_module);

		has_offset_wildcard |= (from_node_type_offset == BLACKLIST_NODE_OFFSET_WILDCARD);
		has_offset_wildcard |= (to_node_type_offset == BLACKLIST_NODE_OFFSET_WILDCARD);

        if (from_node_type_offset > BLACKLIST_NODE_OFFSET_NONE) {
            node->from.offset = from_node_type_offset;
        } else if (from_export) {
            if (dr_sscanf(from_offset_str, "0x%llx", &node->from.edge_hash) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `from` hash '%s' as a uint64\n",
                       from_offset_str);
                dr_global_free(node, sizeof(blacklist_node_type_t));
                return false;
            }
        } else if (dr_sscanf(from_offset_str, "0x%x", &node->from.offset) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the `from` offset '%s' as a uint\n",
                   from_offset_str);
            dr_global_free(node, sizeof(blacklist_node_type_t));
            return false;
        }
        node->to.module_name = cs_strcpy(to_module);
        if (to_node_type_offset > BLACKLIST_NODE_OFFSET_NONE) {
            node->to.offset = to_node_type_offset;
        } else if (to_export) {
            if (dr_sscanf(to_offset_str, "0x%llx", &node->to.edge_hash) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `to` hash '%s' as a uint64\n",
                       to_offset_str);
                dr_global_free(node, sizeof(blacklist_node_type_t));
                return false;
            }
        } else if (dr_sscanf(to_offset_str, "0x%x", &node->to.offset) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the `to` offset '%s' as a uint\n",
                   to_offset_str);
            dr_global_free(node, sizeof(blacklist_node_type_t));
            return false;
        }
        drvector_append(blacklist_node_type_list, node);
        return true;
    }

    from_wildcard = (strcmp(from_module, BLACKLIST_WILDCARD) == 0);
    to_wildcard = (strcmp(to_module, BLACKLIST_WILDCARD) == 0);

    if (from_export && to_export) {
        CS_ERR("BL| There is no such thing as an edge from an export to an export\n");
        return false;
    }

    if ((from_wildcard || from_export) && (to_wildcard || to_export)) {
        blacklist_entry_t *wildcards = CS_ALLOC(sizeof(blacklist_entry_t));
        memset(wildcards, 0, sizeof(blacklist_entry_t));

        if (from_export) {
            wildcards->flags |= BLACKLIST_FLAG_FROM_HASH;
            if (dr_sscanf(from_offset_str, "0x%llx", &wildcards->edge_hash) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `from` hash '%s' as a uint64\n",
                       from_offset_str);
                dr_global_free(wildcards, sizeof(blacklist_entry_t));
                return false;
            }
        } else {
            wildcards->flags |= BLACKLIST_FLAG_FROM_MODULE_WILDCARD;
            if (!to_export)
                wildcards->edge_hash = EDGE_HASH_BOTH_WILDCARD;
            if (dr_sscanf(from_offset_str, "0x%x", &wildcards->from) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `from` offset '%s' as a uint\n",
                       from_offset_str);
                dr_global_free(wildcards, sizeof(blacklist_entry_t));
                return false;
            }
        }

        if (to_export) {
            wildcards->flags |= BLACKLIST_FLAG_TO_HASH;
            if (dr_sscanf(to_offset_str, "0x%llx", &wildcards->edge_hash) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `to` hash '%s' as a uint64\n",
                       to_offset_str);
                dr_global_free(wildcards, sizeof(blacklist_entry_t));
                return false;
            }
        } else {
            wildcards->flags |= BLACKLIST_FLAG_TO_MODULE_WILDCARD;
            if (dr_sscanf(to_offset_str, "0x%x", &wildcards->to) == 0) {
                CS_ERR("BL| Invalid blacklist format: failed to parse the `to` offset '%s' as a uint\n",
                       to_offset_str);
                dr_global_free(wildcards, sizeof(blacklist_entry_t));
                return false;
            }
        }

        hashtable_add(blacklist_edge_table, wildcards, wildcards);
        return true;
    }

    entry = CS_ALLOC(sizeof(pending_blacklist_entry_t));
    memset(entry, 0, sizeof(pending_blacklist_entry_t));

    entry->from.module_name = cs_strcpy(from_module);
    if (from_export) {
        if (to_wildcard) {
            CS_ERR("BL| The blacklist currently does not support wildcard module to an export hash\n");
            goto entry_parse_error;
        }
        if (dr_sscanf(from_offset_str, "0x%llx", &entry->edge_hash) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the edge hash '%s' as a uint64\n",
                   from_offset_str);
            goto entry_parse_error;
        }
        entry->flags |= BLACKLIST_FLAG_FROM_HASH;
    } else {
        if (from_wildcard)
            entry->flags |= BLACKLIST_FLAG_FROM_MODULE_WILDCARD;
        if (dr_sscanf(from_offset_str, "0x%x", &entry->from.offset) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the `from` offset '%s' as a uint\n",
                   from_offset_str);
            goto entry_parse_error;
        }
    }

    entry->to.module_name = cs_strcpy(to_module);
    if (!TEST(BLACKLIST_FLAG_FROM_HASH, entry->flags) && to_export) {
        if (from_wildcard) {
            CS_ERR("BL| The blacklist currently does not support export hash to a wildcard module\n");
            goto entry_parse_error;
        }
        if (dr_sscanf(to_offset_str, "0x%llx", &entry->edge_hash) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the edge hash '%s' as a uint64\n",
                   to_offset_str);
            goto entry_parse_error;
        }
        entry->flags |= BLACKLIST_FLAG_TO_HASH;
    } else {
        if (to_wildcard)
            entry->flags |= BLACKLIST_FLAG_TO_MODULE_WILDCARD;
        if (dr_sscanf(to_offset_str, "0x%x", &entry->to.offset) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the `to` offset '%s' as a uint\n",
                   to_offset_str);
            goto entry_parse_error;
        }
    }

    if (!TEST(BLACKLIST_FLAG_FROM_HASH, entry->flags)) {
        module_entries = establish_module_entries(from_module);
        drvector_append(module_entries, entry);

        CS_LOG("BL| Pending edge #%d for module %s\n", module_entries->entries, from_module);
    }
    if (!TEST(BLACKLIST_FLAG_TO_HASH, entry->flags) && strcmp(from_module, to_module) != 0) {
        module_entries = establish_module_entries(to_module);
        drvector_append(module_entries, entry);

        CS_LOG("BL| Pending edge #%d for module %s\n", module_entries->entries, to_module);
    }

    return true;

entry_parse_error:
    dr_global_free(entry, sizeof(pending_blacklist_entry_t));
    return false;
}

static bool
load_node_entry(char **word_mark) {
    char *module, *offset_str;
    pending_blacklist_entry_t *entry = NULL;
    drvector_t *module_entries;
    bool wildcard;
	uint node_type_offset;

    if (!read_next_word(&module, word_mark, "module specifier"))
        return false;
    if (!read_next_word(&offset_str, word_mark, "node specifier"))
        return false;

	node_type_offset = map_node_type_to_offset(offset_str);
    if (node_type_offset > 0U) {
        blacklist_node_type_t *node = CS_ALLOC(sizeof(blacklist_node_type_t));
        node->from.module_name = cs_strcpy(module);
        node->from.offset = node_type_offset;
        node->to.module_name = NULL;
        drvector_append(blacklist_node_type_list, node);

		has_offset_wildcard |= (node_type_offset == BLACKLIST_NODE_OFFSET_WILDCARD);

        return true;
    }

    wildcard = (strcmp(module, BLACKLIST_WILDCARD) == 0);
    if (wildcard) {
        blacklist_entry_t *wildcard;
        wildcard = CS_ALLOC(sizeof(blacklist_entry_t));
        memset(wildcard, 0, sizeof(blacklist_entry_t));
        wildcard->flags |= BLACKLIST_FLAG_NODE;
        wildcard->edge_hash = EDGE_HASH_NODE_WILDCARD;
        if (dr_sscanf(offset_str, "0x%x", &wildcard->from) == 0) {
            CS_ERR("BL| Invalid blacklist format: failed to parse the node offset '%s' as a uint\n",
                   offset_str);
            dr_global_free(wildcard, sizeof(blacklist_entry_t));
            return false;
        }
        hashtable_add(blacklist_edge_table, wildcard, wildcard);
        return true;
    }

    entry = CS_ALLOC(sizeof(pending_blacklist_entry_t));
    memset(entry, 0, sizeof(pending_blacklist_entry_t));

    entry->from.module_name = cs_strcpy(module);
    if (dr_sscanf(offset_str, "0x%x", &entry->from.offset) == 0) {
        CS_ERR("BL| Invalid blacklist format: failed to parse the node offset '%s' as a uint\n",
               offset_str);
        dr_global_free(entry, sizeof(pending_blacklist_entry_t));
        return false;
    }
    entry->flags |= BLACKLIST_FLAG_NODE;

    module_entries = establish_module_entries(module);
    drvector_append(module_entries, entry);

    CS_LOG("BL| Pending node #%d for module %s\n", module_entries->entries, module);
    return true;
}

static bool
load_blacklist(char *buffer) {
    char *line, next_line[256], *line_mark, *word_mark, *entry_type;

    for (line = strtok_r(buffer, "\r\n", &line_mark); line; line = strtok_r(NULL, "\r\n", &line_mark)) {
        if (line[0] == '#')
            continue;

        strcpy(next_line, line);
        if (!read_first_word(&entry_type, next_line, &word_mark, "entry type"))
            return false;

        if (strcmp(entry_type, BLACKLIST_ACTION_LOAD_MODULE) == 0) {
            if (!load_module_entry(&word_mark))
                return false;
        } else if (strcmp(entry_type, BLACKLIST_ACTION_EDGE) == 0) {
            if (!load_edge_entry(&word_mark))
                return false;
        } else if (strcmp(entry_type, BLACKLIST_ACTION_NODE) == 0) {
            if (!load_node_entry(&word_mark))
                return false;
        } else {
            CS_ERR("BL| Invalid blacklist format: failed to parse '%s' as an action type\n",
                   entry_type);

            return false;
        }
    }

    return true;
}

void
init_blacklist() {
    char blacklist_path[256];
    extern const char *monitor_dataset_dir;
    file_t blacklist_file;
    uint64 size;
    ssize_t read_count;
    char *buffer = NULL;

    pending_blacklist_edge_table = CS_ALLOC(sizeof(hashtable_t));
    hashtable_init_ex(
        pending_blacklist_edge_table,
        PENDING_BLACKLIST_TABLE_KEY_SIZE,
        HASH_STRING,
        true,
        false,
        free_pending_blacklist_module_entries,
        NULL,
        NULL);

    blacklist_edge_table = CS_ALLOC(sizeof(hashtable_t));
    hashtable_init_ex(
        blacklist_edge_table,
        BLACKLIST_TABLE_KEY_SIZE,
        HASH_INTPTR,
        false,
        false,
        free_blacklist_entry,
        hash_blacklist_entry,
        compare_blacklist_entry);

    blacklist_module_load_list = CS_ALLOC(sizeof(drvector_t));
    drvector_init(blacklist_module_load_list, 0x10, false, free_module_load_entry);

    blacklist_node_type_list = CS_ALLOC(sizeof(drvector_t));
    drvector_init(blacklist_node_type_list, 0x10, false, free_blacklist_node_type);

    dr_snprintf(blacklist_path, 256, "%s%s", monitor_dataset_dir, BLACKLIST_FILENAME);
    blacklist_file = dr_open_file(blacklist_path, DR_FILE_READ);
    if (blacklist_file == INVALID_FILE) {
        CS_LOG("BL| Blacklist is not enabled (no configuration file at %s)\n", blacklist_path);
        return;
    }

    dr_file_size(blacklist_file, &size);
    if (size == 0ULL) {
        CS_ERR("BL| Failed to load the blacklist file at %s. Size is zero.\n", blacklist_path);
        goto close_blacklist_file;
    }

    buffer = CS_ALLOC(((size_t)size)+1);
    read_count = dr_read_file(blacklist_file, buffer, (size_t)size);
    if (read_count < (ssize_t)size) {
        CS_ERR("BL| Failed to load the blacklist file at %s. Read only %d of %d bytes\n",
            blacklist_path, read_count, size);
        goto close_blacklist_file;
    }
    buffer[size] = '\0';

    blacklist_enabled = load_blacklist(buffer);

close_blacklist_file:
    dr_close_file(blacklist_file);
    if (size > 0)
        dr_global_free(buffer, ((size_t)size)+1);
}

void
delete_blacklist() {
    // todo...
    drvector_delete(blacklist_module_load_list);
    drvector_delete(blacklist_node_type_list);
}

static void
parse_module_short_name(char *buffer, const char *module_name) {
    char *module_name_dash = strchr(module_name, '-');
    uint module_short_name_length = (module_name_dash == NULL ? strlen(module_name) : module_name_dash - module_name);

    dr_snprintf(buffer, module_short_name_length, "%s", module_name);
}

static void
blacklist_exit_module_load(const char *module_name, char *entry_text) {
    dr_messagebox("Blacklist match in process %d:\n\n    Program loaded module: %s"
                  "\n    Blacklist module: %s\n\nBlackBox will terminate the program.",
                  dr_get_process_id(), module_name, entry_text);
    hashcode_lock_release();
    dr_abort();
}

void
blacklist_bind_module(module_location_t *module) {
    uint i;
    char module_short_name[128];
    drvector_t *pending_entries;
    blacklist_entry_t *entry;
    pending_blacklist_entry_t *pending;

    if (!blacklist_enabled)
        return;

    if (blacklist_module_load_any && module->monitor_data == NULL && module->type == module_type_image)
        blacklist_exit_module_load(module->module_name, BLACKLIST_WILDCARD);
    for (i = 0; i < blacklist_module_load_list->entries; i++) {
        if (strcmp(module->module_name, blacklist_module_load_list->array[i]) == 0)
            blacklist_exit_module_load(module->module_name, module->module_name);
    }

    CS_LOG("BL| Bind module %s\n", module->module_name);

    parse_module_short_name(module_short_name, module->module_name);
    pending_entries = (drvector_t *) hashtable_lookup(pending_blacklist_edge_table, module_short_name);
    if (pending_entries == NULL) {
        CS_LOG("BL| No pending entries for module with short name %s\n", module_short_name);
        return;
    }

    for (i = 0; i < pending_entries->entries; i++) {
        pending = (pending_blacklist_entry_t *) pending_entries->array[i];
        entry = CS_ALLOC(sizeof(blacklist_entry_t));
        memset(entry, 0, sizeof(blacklist_entry_t));
        entry->flags = pending->flags;

        if (TESTANY(BLACKLIST_FLAG_FROM_HASH, pending->flags)) {
            entry->edge_hash = pending->edge_hash;
        } else if (TEST(BLACKLIST_FLAG_FROM_MODULE_WILDCARD, pending->flags)) {
            entry->edge_hash = EDGE_HASH_FROM_WILDCARD;
            entry->from = int2p(pending->from.offset);
        } else {
            entry->from = module->start_pc + pending->from.offset;
        }

        if (!TEST(BLACKLIST_FLAG_NODE, pending->flags)) {
            if (TEST(BLACKLIST_FLAG_TO_HASH, pending->flags)) {
                entry->edge_hash = pending->edge_hash;
            } else if (TEST(BLACKLIST_FLAG_TO_MODULE_WILDCARD, pending->flags)) {
                entry->edge_hash = EDGE_HASH_TO_WILDCARD;
                entry->to = int2p(pending->to.offset);
            } else {
                entry->to = module->start_pc + pending->to.offset;
            }
        }

        hashtable_add(blacklist_edge_table, entry, entry);
        CS_LOG("BL| Bound blacklist entry [0x%x] "PX" -> "PX" (0x%llx) in module %s\n",
               entry->flags, entry->from, entry->to, entry->edge_hash, module_short_name);
    }
}

void
blacklist_unbind_module(module_location_t *module) {
    uint i;
    char module_short_name[128];
    drvector_t *pending_entries;
    blacklist_entry_t removal;
    pending_blacklist_entry_t *pending;

    if (!blacklist_enabled)
        return;

    parse_module_short_name(module_short_name, module->module_name);
    pending_entries = (drvector_t *) hashtable_lookup(pending_blacklist_edge_table, module_short_name);
    if (pending_entries == NULL)
        return;

    for (i = 0; i < pending_entries->entries; i++) {
        pending = (pending_blacklist_entry_t *) pending_entries->array[i];
        memset(&removal, 0, sizeof(blacklist_entry_t));

        if (TEST(BLACKLIST_FLAG_FROM_HASH, removal.flags)) {
            removal.edge_hash = pending->edge_hash;
        } else if (TEST(BLACKLIST_FLAG_FROM_MODULE_WILDCARD, pending->flags)) {
            removal.edge_hash = EDGE_HASH_FROM_WILDCARD;
            removal.from = int2p(pending->from.offset);
        } else {
            removal.from = module->start_pc + pending->from.offset;
        }

        if (!TEST(BLACKLIST_FLAG_NODE, pending->flags)) {
            if (TEST(BLACKLIST_FLAG_TO_HASH, removal.flags)) {
                removal.edge_hash = pending->edge_hash;
            } else if (TEST(BLACKLIST_FLAG_TO_MODULE_WILDCARD, pending->flags)) {
                removal.edge_hash = EDGE_HASH_TO_WILDCARD;
                removal.to = int2p(pending->to.offset);
            } else {
                removal.to = module->start_pc + pending->to.offset;
            }
        }

        hashtable_remove(blacklist_edge_table, &removal);
    }
}

static void
blacklist_exit_node(app_pc tag, char *entry_text) {
    dr_messagebox("Blacklist match in process %d:\n\n    Program node: "PX
                  "\n    Blacklist node: %s\n\nBlackBox will terminate the program.",
                  dr_get_process_id(), tag, entry_text);
    hashcode_lock_release();
    dr_abort();
}

void
check_blacklist_node(module_location_t *module, app_pc tag) {
    char entry_text[256];
    blacklist_entry_t lookup = {0};
    lookup.from = tag;

    if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
        dr_snprintf(entry_text, 256, "%s "PX,
                    module->module_name, MODULAR_PC(module, tag));
        blacklist_exit_node(tag, entry_text);
    }

    lookup.edge_hash = EDGE_HASH_NODE_WILDCARD;
    lookup.from = MODULAR_PC(module, tag);
    if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
        dr_snprintf(entry_text, 256, "* "PX, MODULAR_PC(module, tag));
        blacklist_exit_node(tag, entry_text);
    }
}

static void
blacklist_exit_edge(app_pc from, app_pc to, char *entry_text) {
    dr_messagebox("Blacklist match in process %d:\n\n    Program edge: "PX" -> "PX
                  "\n    Blacklist edge: %s\n\nBlackBox will terminate the program.",
                  dr_get_process_id(), from, to, entry_text);
    hashcode_lock_release();
    dr_abort();
}

static inline bool
blacklist_node_matches_module(blacklist_node_t *node, module_location_t *module) {
	return (strcmp(node->module_name, BLACKLIST_WILDCARD) == 0 ||
            strcmp(node->module_name, module->module_name) == 0);
}

static inline bool
blacklist_node_matches_offset(blacklist_node_t *node, module_location_t *module,
                              app_pc tag, bb_state_t *state) {
	if (node->offset == BLACKLIST_NODE_OFFSET_WILDCARD)
		return true;
    if (node->offset == BLACKLIST_NODE_OFFSET_ABNORMAL_RETURN && IS_BB_UNEXPECTED_RETURN(state))
		return true;
    if (node->offset == BLACKLIST_NODE_OFFSET_WHITE_BOX && IS_BB_WHITE_BOX(module, state))
		return true;
    if (node->offset == BLACKLIST_NODE_OFFSET_BLACK_BOX && IS_BB_BLACK_BOX(state))
		return true;

	return node->offset == p2int(MODULAR_PC(module, tag));
}

static bool
blacklist_node_matches(blacklist_node_t *node, module_location_t *module, app_pc tag,
                       bb_state_t *state, bb_hash_t edge_hash) {
    if (node->module_name == NULL) // marker for node-only match
        return true;

    if (blacklist_node_matches_module(node, module) &&
	    blacklist_node_matches_offset(node, module, tag, state)) {
        return true;
    }

    if (edge_hash > 0ULL) {
        if (strcmp(node->module_name, BLACKLIST_EXPORT) == 0 && edge_hash == node->edge_hash)
            return true;
    }

    return false;
}

static void
print_blacklist_node_type(char *buffer, int length, blacklist_node_type_t *node) {
    char from_offset[24], to_offset[24];
	const char *node_type_name;

	node_type_name = map_node_type_offset_to_entry_text(node->from.offset);
    if (node_type_name != NULL)
        dr_snprintf(from_offset, 24, node_type_name);
    else if (strcmp(node->from.module_name, BLACKLIST_EXPORT) == 0)
        dr_snprintf(from_offset, 24, "0x%llx", node->from.edge_hash);
    else
        dr_snprintf(from_offset, 24, "0x%x", node->from.offset);

    if (node->to.module_name == NULL) {
        dr_snprintf(buffer, length, "%s %s",
                    node->from.module_name, from_offset);
    } else {
		node_type_name = map_node_type_offset_to_entry_text(node->to.offset);
		if (node_type_name != NULL)
			dr_snprintf(to_offset, 24, node_type_name);
        else if (strcmp(node->to.module_name, BLACKLIST_EXPORT) == 0)
            dr_snprintf(to_offset, 24, "0x%llx", node->to.edge_hash);
        else
            dr_snprintf(to_offset, 24, "0x%x", node->to.offset);

        dr_snprintf(buffer, length, "%s %s %s %s",
                    node->from.module_name, from_offset, node->to.module_name, to_offset);
    }
}

void
check_blacklist_edge(module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
                     bb_state_t *from_state, bb_state_t *to_state, bb_hash_t edge_hash, graph_edge_type edge_type)
{
    char entry_text[256];
    blacklist_entry_t lookup = {0};

    if (edge_hash == 0ULL) {
        lookup.from = from;
        lookup.to = to;
        if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
            dr_snprintf(entry_text, 256, "%s "PX" -> %s "PX,
                        from_module->module_name, MODULAR_PC(from_module, from),
                        to_module->module_name, MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }
        lookup.edge_hash = EDGE_HASH_FROM_WILDCARD;
        lookup.from = MODULAR_PC(from_module, from);
        if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
            dr_snprintf(entry_text, 256, "* "PX" -> %s "PX,
                        MODULAR_PC(from_module, from),
                        to_module->module_name, MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }
        lookup.edge_hash = EDGE_HASH_BOTH_WILDCARD;
        lookup.to = MODULAR_PC(to_module, to);
        if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
            dr_snprintf(entry_text, 256, "* "PX" -> * "PX,
                        MODULAR_PC(from_module, from), MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }
        lookup.edge_hash = EDGE_HASH_TO_WILDCARD;
        lookup.from = from;
        if (hashtable_lookup(blacklist_edge_table, &lookup) != NULL) {
            dr_snprintf(entry_text, 256, "%s "PX" -> * "PX,
                        from_module->module_name, MODULAR_PC(from_module, from),
                        MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }
    } else {
        blacklist_entry_t *found;

        lookup.from = from;
        lookup.edge_hash = edge_hash;
        found = hashtable_lookup(blacklist_edge_table, &lookup);
        if (found != NULL && !TEST(BLACKLIST_FLAG_FROM_MODULE_WILDCARD, found->flags)) {
            dr_snprintf(entry_text, 256, "%s "PX" -> <export> 0x%llx",
                        from_module->module_name, MODULAR_PC(from_module, from), edge_hash);
            blacklist_exit_edge(from, to, entry_text);
        }

        lookup.from = MODULAR_PC(from_module, from);
        found = hashtable_lookup(blacklist_edge_table, &lookup);
        if (found != NULL && TEST(BLACKLIST_FLAG_FROM_MODULE_WILDCARD, found->flags)) {
            dr_snprintf(entry_text, 256, "* "PX" -> <export> 0x%llx",
                        MODULAR_PC(from_module, from), edge_hash);
            blacklist_exit_edge(from, to, entry_text);
        }

        lookup.from = NULL;
        lookup.to = to;
        found = hashtable_lookup(blacklist_edge_table, &lookup);
        if (found != NULL && !TEST(BLACKLIST_FLAG_TO_MODULE_WILDCARD, found->flags)) {
            dr_snprintf(entry_text, 256, "<export> 0x%llx -> %s "PX,
                        edge_hash, to_module->module_name, MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }

        lookup.to = MODULAR_PC(to_module, to);
        found = hashtable_lookup(blacklist_edge_table, &lookup);
        if (found != NULL && TEST(BLACKLIST_FLAG_TO_MODULE_WILDCARD, found->flags)) {
            dr_snprintf(entry_text, 256, "<export> 0x%llx -> * "PX,
                        edge_hash, MODULAR_PC(to_module, to));
            blacklist_exit_edge(from, to, entry_text);
        }
    }

    if (is_node_type(from_module, from_state) || is_node_type(from_module, to_state) || has_offset_wildcard) {
        uint i;
        blacklist_node_type_t *node;

        CS_DET("Checking abnormal return "PX" -> "PX" (0x%llx) against list of %d entries\n",
               from, to, edge_hash, blacklist_node_type_list->entries);

        for (i = 0; i < blacklist_node_type_list->entries; i++) {
            node = (blacklist_node_type_t *) blacklist_node_type_list->array[i];
            if (blacklist_node_matches(&node->from, from_module, from, from_state, edge_hash) &&
                blacklist_node_matches(&node->to, to_module, to, to_state, edge_hash)) {
                print_blacklist_node_type(entry_text, 256, node);
                if (node->to.module_name == NULL) {
					switch (node->from.offset) { /* ignore certain trusted states for node-only match */
						case BLACKLIST_NODE_OFFSET_ABNORMAL_RETURN:
							/* trusted abnormal return */
							if (!IS_BB_MONITOR_MISS(from_state) && is_abnormal_return(from_module, from))
								continue;
							break;
						case BLACKLIST_NODE_OFFSET_WILDCARD:  /* trusted static node */
						case BLACKLIST_NODE_OFFSET_WHITE_BOX: /* trusted dynamic node */
						case BLACKLIST_NODE_OFFSET_BLACK_BOX:
							if (!IS_BB_MONITOR_MISS(from_state))
								continue;
							break;
					}
                    blacklist_exit_node(from, entry_text);
                } else {
                    blacklist_exit_edge(from, to, entry_text);
                }
            }
        }
    }

    if (edge_type == unexpected_return_edge && !is_abnormal_return(from_module, from)) {
        CS_LOG("BL| New abnormal return at %s("PX")\n",
               from_module->module_name, MODULAR_PC(from_module, from));
    }
}

/****** private functions *******/

static drvector_t *
establish_module_entries(const char *module_name) {
    drvector_t *entries = (drvector_t *) hashtable_lookup(pending_blacklist_edge_table, (void *) module_name);
    if (entries == NULL) {
        entries = CS_ALLOC(sizeof(drvector_t));
        drvector_init(entries, 0x10, false, free_pending_blacklist_entry);
        hashtable_add(pending_blacklist_edge_table, (void *) module_name, entries);

        ASSERT(hashtable_lookup(pending_blacklist_edge_table, (void *) module_name) != NULL);
    }
    return entries;
}

static uint
hash_blacklist_entry(void *e) {
    blacklist_entry_t *entry = (blacklist_entry_t *) e;

    uint hash = (uint) entry->from;
    if (entry->to != NULL)
        hash = hash ^ (hash << 5) ^ (uint) entry->to;
    if (entry->edge_hash > 0ULL) {
        hash = hash ^ (hash << 5) ^ (uint) entry->edge_hash;
        hash = hash ^ (hash << 5) ^ (uint) (entry->edge_hash >> 8);
    }
    return hash;
}

static bool
compare_blacklist_entry(void *a, void *b) {
    blacklist_entry_t *first = (blacklist_entry_t *) a, *second = (blacklist_entry_t *) b;

    return first->from == second->from && first->to == second->to &&
           first->edge_hash == second->edge_hash;
}

static void
free_pending_blacklist_module_entries(void *e) {
    drvector_t *entries = (drvector_t *) e;

    drvector_delete(entries);
    dr_global_free(entries, sizeof(drvector_t));
}

static void
free_pending_blacklist_entry(void *e) {
    pending_blacklist_entry_t *entry = (pending_blacklist_entry_t *) e;

    if (!TEST(BLACKLIST_FLAG_FROM_HASH, entry->flags))
        cs_strfree(entry->from.module_name);
    if (!TEST(BLACKLIST_FLAG_TO_HASH, entry->flags))
        cs_strfree(entry->to.module_name);
    dr_global_free(entry, sizeof(pending_blacklist_entry_t));
}

static void
free_blacklist_entry(void *e) {
    dr_global_free(e, sizeof(blacklist_entry_t));
}

static void
free_module_load_entry(void *e) {
    char *name = (char *) e;
    cs_strfree(name);
}

static void
free_blacklist_node_type(void *e) {
    blacklist_node_type_t *node = (blacklist_node_type_t *) e;

    if (node->to.module_name != NULL) // hack: node-only marker
        cs_strfree(node->from.module_name);
    cs_strfree(node->to.module_name);
    dr_global_free(node, sizeof(blacklist_node_type_t));
}
