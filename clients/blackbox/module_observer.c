#include "link_observer.h"
#include <string.h>
#include "../../core/x86/instrument.h"
#include "../../core/os_shared.h"
#include "../../core/native_exec.h"
#include "../../core/module_shared.h"
#include "../../core/win32/ntdll.h"
#include "../../core/utils.h"
#include "drsyms.h"
#include "crowd_safe_util.h"
#include "crowd_safe_trace.h"
#include "basic_block_observer.h"
#include "basic_block_hashtable.h"
#include "indirect_link_observer.h"
#include "crowd_safe_gencode.h"
#include "execution_monitor.h"
#include "blacklist.h"

#ifdef UNIX
# include "../../core/unix/module.h"
#endif

/* Template instantiation: module_vector_t */
#define VECTOR_NAME_KEY module_vector
#define VECTOR_ENTRY_TYPE module_location_t*
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: module_vector_t */
#define VECTOR_NAME_KEY module_vector
#define VECTOR_ENTRY_TYPE module_location_t*
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

#define FUNCTION_ID_LENGTH 256

/**** Public Fields ****/

/* Template instantiation: relocation_target_table_t */
#define HASHTABLE_NAME_KEY relocation_target_table
#define HASHTABLE_KEY_TYPE ptr_uint_t
#define HASHTABLE_PAYLOAD_TYPE ptr_uint_t
#define HASHTABLE_IS_EMPTY(x) x == 0U
#define HASHTABLE_INIT_EMPTY 0U
#include "../drcontainers/drhashtablex.h"

/* Template instantiation: export_hashtable_t */
#define HASHTABLE_NAME_KEY export_hashtable
#define HASHTABLE_PAYLOAD_TYPE function_export_t
#define HASHTABLE_IS_EMPTY(x) x.hash == 0ULL
#define HASHTABLE_INIT_EMPTY { 0ULL, NULL }
#include "../drcontainers/drhashtablex.h"

//   --- cross-module target hashtable ---
// dr_get_main_module()->entry_point | "!main"
// exports
//   · named: address | module-name!function-name
//   · ordinal: address | module-name@ordinal(#)
export_hashtable_t *export_hashes;

/**** Private Fields ****/

static void (*module_loaded_callback)(void *drcontext, const module_data_t *info, bool loaded);
static void (*module_unloaded_callback)(void *drcontext, const module_data_t *info);
static const int trampoline_size = 0x10;

static module_vector_t *module_list;
static bb_hash_t *black_box_singleton_list;
static uint *black_box_singleton_count;
static ushort *image_instance_index;

typedef struct anonymous_module_metadata_t anonymous_module_metadata_t;
static struct anonymous_module_metadata_t {
    short module_type;
    char *module_name;
    uint version_index;
} *anonymous_module_metadata;

typedef struct pending_gencode_edge_t pending_gencode_edge_t;
struct pending_gencode_edge_t {
    app_pc from;
    module_location_t *from_module;
    graph_edge_type edge_type;
};

/* Template instantiation: chunk_hash_vector_t */
#define VECTOR_NAME_KEY chunk_hash_vector
#define VECTOR_ENTRY_TYPE bb_hash_t
#define VECTOR_COMPARISON_TYPE bb_hash_t
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: chunk_hash_vector_t */
#define VECTOR_NAME_KEY chunk_hash_vector
#define VECTOR_ENTRY_TYPE bb_hash_t
#define VECTOR_COMPARISON_TYPE bb_hash_t
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

#define CHUNK_WORDS 0x4
#define CHUNKS_PER_PAGE 0x80
#define CHUNK_INDEX(tag) (p2int(tag) >> 5) & 0x7f;

typedef struct shadow_page_t shadow_page_t;
struct shadow_page_t {
    app_pc start_pc;
    drvector_t *pending_edges;
    bool executable;
#ifdef GENCODE_CHUNK_STUDY
    chunk_hash_vector_t chunks[CHUNKS_PER_PAGE];
    bb_hash_t last_chunk_hash[CHUNKS_PER_PAGE];
    bool chunk_flushed[CHUNKS_PER_PAGE];
    bool ever_visited_after_flush[CHUNKS_PER_PAGE];
    bool ever_flushed;
#endif
};

/* Template instantiation: shadow_page_table_t */
#define VECTOR_NAME_KEY shadow_page_table
#define VECTOR_ENTRY_TYPE shadow_page_t*
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: shadow_page_table_t */
#define VECTOR_NAME_KEY shadow_page_table
#define VECTOR_ENTRY_TYPE shadow_page_t*
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

static shadow_page_table_t *shadow_page_table;
#define DEFAULT_SHADOW_PAGE_OWNER (module_location_t*)int2p(1)

typedef struct _stack_frame_t {
    union {
        app_pc return_address;
        app_pc writer_tag;
    };
    module_location_t *module;
} stack_frame_t;

typedef struct _executable_write_t {
    app_pc start;
    app_pc end;
    uint frame_count;
    stack_frame_t *frames;
} executable_write_t;

/* Template instantiation: executable_write_list_t */
#define VECTOR_NAME_KEY executable_write_list
#define VECTOR_ENTRY_TYPE executable_write_t
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: executable_write_list_t */
#define VECTOR_NAME_KEY executable_write_list
#define VECTOR_ENTRY_TYPE executable_write_t
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

static executable_write_list_t *executable_write_list;

#ifdef GENCODE_CHUNK_STUDY
typedef struct chunk_change_t chunk_change_t;
struct chunk_change_t {
    uint count;
    report_mask_t mask;
}
*redundant_flush_report_singleton,
*redundant_flush_report_multiple,
*valid_flush_report,
*flush_report_counter,
*rotation_report;
#endif

typedef ushort relocation_entry_t;

/* Template instantiation: relocation_vector_t */
#define VECTOR_NAME_KEY relocation_vector
#define VECTOR_ENTRY_TYPE relocation_entry_t
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: relocation_vector_t */
#define VECTOR_NAME_KEY relocation_vector
#define VECTOR_ENTRY_TYPE relocation_entry_t
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

typedef struct relocation_table_page_t relocation_table_page_t;
struct relocation_table_page_t {
    app_pc page_base;
    relocation_vector_t *relocations;
};

/* Template instantiation: relocation_table_t */
#define VECTOR_NAME_KEY relocation_table
#define VECTOR_ENTRY_TYPE relocation_table_page_t
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvector.h"

/* Template instantiation: relocation_table_t */
#define VECTOR_NAME_KEY relocation_table
#define VECTOR_ENTRY_TYPE relocation_table_page_t
#define VECTOR_COMPARISON_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#define VECTOR_SORTED 1
#include "../drcontainers/drvectorx.h"

#define KEY_SIZE 9

#define MAX_MODULE_NAME_LENGTH 100

typedef struct _xhash_module_t {
    module_location_t *module;
    bool write_xhash;
} xhash_module_t;

#define MODULE_LOCK dynamo_vm_areas_lock();
#define MODULE_UNLOCK dynamo_vm_areas_unlock();

#define CHECK_SIGNATURE(sig) ((*sig == 'P') && (*(sig+1) == 'E') && \
    (*(sig+2) == 0) && (*(sig+3) == 0))

#define RELOCATIONS_STRIPPED(sig) ((*(uint*)(sig + 0x16) & 0x1U) > 0)

// ignore "RT", "Shared", or anything starting with "/"
#define IS_IGNORABLE_SECTION(ptr) ((*ptr == '/') || (*ptr == 'R') || (*ptr == 'S'))

#define IS_SECTION(ptr) ((*ptr == '.') || (*ptr == '_') || \
    (((*(uint*)ptr) == 0x416e696dU) && ((*(uint*)(ptr + sizeof(uint))) == 0x4c54U)))

#define IS_RELOCATION_SECTION(ptr) (((*(uint*)ptr) == 0x6c65722eU) && ((*(uint*)(ptr + sizeof(uint))) == 0x636fU))

//((*sec == '.') && (*(sec+1) == 'r') \
//    && (*(sec+2) == 'e') && (*(sec+3) == 'l') && (*(sec+4) == 'o') \
//    && (*(sec+5) == 'c') && (*(sec+6) == 0))

#define MAX_BLACK_BOX_SINGLETONS 10

static uint *module_count;

#define XHASH_KEY_SIZE 4
#define XHASH_WRITTEN_MARKER &"written"
static hashtable_t *xhash_table;

/**** Private Prototypes ****/

static void
free_module_location(void *module);

static void
free_shadow_page(void *page);

static void
free_executable_write(executable_write_t write);

static void
notify_module_loaded(void *drcontext, const module_data_t *info, bool loaded);

static void
notify_module_unloaded(void *drcontext, const module_data_t *info);

static void
add_shadow_page(dcontext_t *dcontext, app_pc base, bool safe_to_read);

static void
remove_shadow_page(dcontext_t *dcontext, app_pc base);

static uint
get_app_stacktrace(priv_mcontext_t *mc, uint max_frames, stack_frame_t *frames);

static void
copy_appstack(executable_write_t *dst, executable_write_t *src);

static void
take_write_stack_snapshot(dcontext_t *dcontext, executable_write_t *write, app_pc writer_tag);

#ifdef GENCODE_CHUNK_STUDY
static void
update_shadow_page_chunks(shadow_page_t *page);

static bb_hash_t
hash_chunk(uint64 *code);
#endif

#ifdef WINDOWS
static void
load_relocations(module_location_t *location, const char *module_path);

static void
initialize_module_exports(module_location_t *module, const char *module_path);

static void
clear_module_exports(module_location_t *module);

# ifdef CROWD_SAFE_DYNAMIC_IMPORTS
static void
find_get_proc_address(module_location_t *module);
# endif
#endif

static void
create_anonymous_module(dcontext_t *dcontext, app_pc start, app_pc end, anonymous_module_metadata_t *metadata);

static void
expand_anonymous_module(module_location_t *module, app_pc start, app_pc end);

static void
subsume_overlapping_modules(module_location_t *module, app_pc region_start, app_pc region_end, char *caller);

static void
register_module(module_location_t *module, const char *module_path);

static void
unregister_module(module_location_t *module);

static void
print_module_load(module_location_t *module);

static void
print_module_unload(module_location_t *module);

static int
compare_hashes(bb_hash_t first, bb_hash_t second);

static int
compare_executable_write_with_pc(executable_write_t write, app_pc second);

static int
compare_module_vs_tag(module_location_t *module, app_pc tag);

static int
compare_page_vs_tag(shadow_page_t *page, app_pc tag);

static int
compare_relocation_page(relocation_table_page_t relocation_page, app_pc page);

static int
compare_relocation_entry_with_page_offset(ushort relocation_entry, ushort page_offset);

static inline bool
is_syscall_trampoline_name(char *name);

static char *
init_function_id(const char *basename);

static bool
register_xhash_module(module_location_t *module);

static void
free_function_export(function_export_t export);

#ifdef UNIX
static void
resolve_pending_trampolines();

static void
write_trampoline(trampoline_tracker *trampoline, app_pc function_caller,
    int caller_exit_ordinal, graph_edge_type edge_type);
#endif

/**** Public Functions ****/

void
init_module_observer(bool is_fork) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    drsym_init(0);

    if (!is_fork) {
        app_pc s;
        bb_hash_t hash;
        module_handle_t ntdllh = get_ntdll_base();

        module_count = (uint *)CS_ALLOC(sizeof(uint));
        *module_count = 0;

        export_hashes = (export_hashtable_t*)CS_ALLOC(sizeof(export_hashtable_t));
        export_hashtable_init_ex(
            export_hashes,
            KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            free_function_export,
            NULL, /* no custom hashing */
            NULL);
        for (s = SYSCALL_SINGLETON_START; s < SYSCALL_SINGLETON_END; s++) {
            char *syscall_export_name = (char *)CS_ALLOC(FUNCTION_ID_LENGTH);
            syscall_export_name[0] = '\0';
            dr_snprintf(syscall_export_name, 32, "syscall#%d", s);
            hash = string_hash(syscall_export_name);
            {
                function_export_t export = { hash, syscall_export_name };
                export_hashtable_add(export_hashes, s, export); /* no xhash report for these */
            }
        }

        if (CROWD_SAFE_RECORD_XHASH()) {
            xhash_table = CS_ALLOC(sizeof(hashtable_t));
            hashtable_init_ex(xhash_table, XHASH_KEY_SIZE, HASH_STRING,
                              true/*strdup*/, false, NULL, NULL, NULL);
        }

        unknown_module.start_pc = NULL;
        unknown_module.end_pc = NULL;
        unknown_module.relocation_table = NULL;
        unknown_module.relocation_targets = NULL;
        unknown_module.monitor_data = NULL;
        unknown_module.type = module_type_meta;
        unknown_module.module_name = UNKNOWN_MODULE_NAME;
        unknown_module.black_box_singleton = 0ULL;
        unknown_module.black_box_singleton_state = NULL;
        unknown_module.black_box_entry = 0ULL;
        unknown_module.black_box_exit = 0ULL;
        unknown_module.gencode_from_tags = NULL;
        unknown_module.image_instance_id = 0;
#ifdef WINDOWS
        unknown_module.version = 0;
        unknown_module.checksum = 0;
        unknown_module.timestamp = 0;
#endif

        system_module.start_pc = NULL;
        system_module.end_pc = NULL;
        system_module.relocation_table = NULL;
        system_module.relocation_targets = NULL;
        system_module.monitor_data = NULL;
        system_module.type = module_type_meta;
        system_module.module_name = SYSCALL_MODULE_NAME;
        system_module.black_box_singleton = 0ULL;
        system_module.black_box_singleton_state = NULL;
        system_module.black_box_entry = 0ULL;
        system_module.black_box_exit = 0ULL;
        system_module.gencode_from_tags = NULL;
        system_module.image_instance_id = 0;
#ifdef WINDOWS
        system_module.version = 0;
        system_module.checksum = 0;
        system_module.timestamp = 0;
#endif

        anonymous_module_metadata = (anonymous_module_metadata_t *)CS_ALLOC(sizeof(anonymous_module_metadata_t));
        anonymous_module_metadata->module_type = module_type_anonymous;
        anonymous_module_metadata->module_name = ANONYMOUS_MODULE_NAME;
        anonymous_module_metadata->version_index = 0;

        module_loaded_callback = notify_module_loaded;
        dr_register_module_load_event(module_loaded_callback);
        module_unloaded_callback = notify_module_unloaded;
        dr_register_module_unload_event(module_unloaded_callback);

        module_list = (module_vector_t*)CS_ALLOC(sizeof(module_vector_t));
        module_vector_init(module_list, 20U, false, NULL, compare_module_vs_tag);

        if (CROWD_SAFE_BB_GRAPH()) {
            shadow_page_table = (shadow_page_table_t*)CS_ALLOC(sizeof(shadow_page_table_t));
            shadow_page_table_init(shadow_page_table, 32U, false, free_shadow_page, compare_page_vs_tag);

            executable_write_list = (executable_write_list_t *) CS_ALLOC(sizeof(executable_write_list_t));
            executable_write_list_init(executable_write_list, 32U, false, free_executable_write,
                                       compare_executable_write_with_pc);
        }

        black_box_singleton_list = (bb_hash_t *)CS_ALLOC(MAX_BLACK_BOX_SINGLETONS * sizeof(bb_hash_t));
        black_box_singleton_count = (uint *)CS_ALLOC(sizeof(uint));
        *black_box_singleton_count = 0;

        image_instance_index = (ushort *)CS_ALLOC(sizeof(ushort));
        *image_instance_index = 1;
    }

#ifdef GENCODE_CHUNK_STUDY
    redundant_flush_report_singleton = CS_ALLOC(sizeof(chunk_change_t));
    redundant_flush_report_singleton->count = 0;
    init_report_mask(&redundant_flush_report_singleton->mask, 0xff, 0xffffffffU);

    redundant_flush_report_multiple = CS_ALLOC(sizeof(chunk_change_t));
    redundant_flush_report_multiple->count = 0;
    init_report_mask(&redundant_flush_report_multiple->mask, 0xff, 0xffffffffU);

    valid_flush_report = CS_ALLOC(sizeof(chunk_change_t));
    valid_flush_report->count = 0;
    init_report_mask(&valid_flush_report->mask, 0xff, 0xffffffffU);

    flush_report_counter = CS_ALLOC(sizeof(chunk_change_t));
    flush_report_counter->count = 0;
    init_report_mask(&flush_report_counter->mask, 0xf, 0xffffffffU);

    rotation_report = CS_ALLOC(sizeof(chunk_change_t));
    rotation_report->count = 0;
    init_report_mask(&rotation_report->mask, 0xf, 0xffffffffU);
#endif
}

void
notify_dynamo_initialized() {
#ifdef UNIX
    register_plt_trampolines();
#endif
}

static void /* callback */
notify_module_loaded(void *dcontext, const module_data_t *data, bool loaded) {
    module_location_t *module;
    char *module_name = NULL;

    module = (module_location_t *)CS_ALLOC(sizeof(module_location_t));
    module->start_pc = data->start;
    module->end_pc = data->end;
    module->black_box_singleton = 0ULL;
    module->black_box_singleton_state = NULL;
    module->gencode_from_tags = NULL;
    module->version = data->file_version.version;
    module->checksum = data->checksum;
    module->timestamp = data->timestamp;
    module->relocation_table = NULL;
    module->relocation_targets = NULL;
    module->intra_module_singleton_edge_misses = 0UL;
#ifdef MONITOR_UIBP_ONLINE
    init_unexpected_ibt(module);
#endif

    MODULE_LOCK
    module->image_instance_id = (*image_instance_index)++;
    MODULE_UNLOCK

    module_name = (char*)data->names.file_name;
    if ((module_name == NULL) || (strlen(module_name) == 0))
        module_name = (char*)data->names.module_name;
    if ((module_name == NULL) || (strlen(module_name) == 0))
        module_name = (char*)data->names.rsrc_name;
    ASSERT((module_name != NULL) && (strlen(module_name) > 0));
    module->module_name = (char*)CS_ALLOC(strlen(module_name) + 1);
    strcasecpy(module->module_name, module_name, true);

    if (strmincmp(module->module_name, "dynamorio.dll") == 0) {
        module->type = module_type_dynamo;

        module->black_box_entry = 0ULL;
        module->black_box_exit = 0ULL;
    } else {
        char black_box_boundary_name[128];

        module->type = module_type_image;

        print_blackbox_entry(black_box_boundary_name, 128, module->module_name);
        module->black_box_entry = string_hash(black_box_boundary_name);
        print_blackbox_exit(black_box_boundary_name, 128, module->module_name);
        module->black_box_exit = string_hash(black_box_boundary_name);
    }

    get_monitor_module(module);
    register_module(module, data->full_path);
    initialize_module_exports(module, data->full_path);

    hashcode_lock_acquire();
    blacklist_bind_module(module);
    hashcode_lock_release();

    if (CROWD_SAFE_BB_GRAPH()) { // this stuff must happen at the point main() is loaded
        module_data_t *main = dr_get_main_module();
        if ((main != NULL) && (main->start == data->start)) {
            uint i;
            shadow_page_t *page;

            write_meta_header();

            MODULE_LOCK
            for (i = 0; i < shadow_page_table->entries; i++) { // cs-todo: missing some shadow pages at this point
                page = shadow_page_table->array[i];
                if (page->pending_edges->entries == 0) {
                    pending_gencode_edge_t *pending_edge = CS_ALLOC(sizeof(pending_gencode_edge_t));
                    pending_edge->from = data->entry_point;
                    pending_edge->from_module = module;
                    pending_edge->edge_type = gencode_perm_edge;
                    drvector_append(page->pending_edges, pending_edge);
                }
            }
            MODULE_UNLOCK
        }
    }
}

static void /* callback */
notify_module_unloaded(void *dcontext, const module_data_t *data) {
    MODULE_LOCK {
    module_location_t *module = module_vector_search(module_list, data->start);
    MODULE_UNLOCK

    if (module != NULL) {
        hashcode_lock_acquire();
        clear_module_exports(module);
        blacklist_unbind_module(module);
        hashcode_lock_release();

        unregister_module(module);
    } else {
        CS_ERR("Error! Module unload event for a module that is not in the list: %s\n", data->names.file_name);
    }}
}

module_location_t*
get_module_for_address(app_pc address) {
    extern vm_area_vector_t *landing_pad_areas;
    module_location_t *found = NULL;

    if (((address >= SYSCALL_SINGLETON_START) && (address <= SYSCALL_SINGLETON_END)) || (address == PROCESS_ENTRY_POINT))
        return &system_module;

    MODULE_LOCK
    found = module_vector_search(module_list, address);
    MODULE_UNLOCK

    if (found == NULL)
        found = &unknown_module;

    return found;
}

short
get_next_relocation(module_location_t *module, app_pc search_start, app_pc search_end) {
    app_pc absolute_search_start_page = int2p(p2int(search_start) & 0xFFFFF000U);
    app_pc operand_page = int2p(absolute_search_start_page - module->start_pc);
    app_pc absolute_search_end_page = int2p(p2int(search_end) & 0xFFFFF000U);
    relocation_table_page_t *relocation_page = relocation_table_search((relocation_table_t*)module->relocation_table, operand_page);
    if (relocation_page != NULL) {
        relocation_entry_t *relocation;
        relocation_entry_t page_search_start_offset = (relocation_entry_t)(p2int(search_start) & 0xfff);
        relocation_entry_t page_search_end_offset;
        if (absolute_search_start_page != absolute_search_end_page)
            page_search_end_offset = (relocation_entry_t)0xfff;
        else
            page_search_end_offset = (relocation_entry_t)(p2int(search_end) & 0xfff);

        relocation = relocation_vector_overlap_search(relocation_page->relocations,
            page_search_start_offset, page_search_end_offset);
        if (relocation != NULL) {
            relocation_entry_t relocation_entry = *relocation;
            app_pc absolute_operand_address;
            if ((relocation_entry & 0xf000U) != 0x3000U)
                return -1;
            absolute_operand_address = absolute_search_start_page + (relocation_entry & 0xfff);
            return (short)(absolute_operand_address - search_start);
        }
    }

    if (absolute_search_start_page != absolute_search_end_page) {
        short end_page_relocation = get_next_relocation(module, absolute_search_end_page, search_end);
        if (end_page_relocation < 0)
            return -1;
        else
            return (short)(p2int(absolute_search_end_page - search_start) + end_page_relocation);
    } else {
        return -1;
    }
}

void
code_area_created(dcontext_t *dcontext, app_pc start, app_pc end) {
    module_location_t *existing;

    if (!CROWD_SAFE_MODULE_LOG())
        return;

    MODULE_LOCK;
    existing = module_vector_overlap_search(module_list, start, end);
    MODULE_UNLOCK;

    if (existing != NULL) {
        if (existing->type == module_type_anonymous) {
            subsume_overlapping_modules(existing, start, existing->start_pc-1, __FUNCTION__);
            subsume_overlapping_modules(existing, existing->end_pc+1, end, __FUNCTION__);
            expand_anonymous_module(existing, start, end);
        }
    } else {
        create_anonymous_module(dcontext, start, end, anonymous_module_metadata);
    }
}

// This function is often called with fragments of the module, which represent internal
// reorganization of the module. Ideally these could be filtered out, but the accounting
// structure of vmareas.c does not match our anonymous module structure.
void
code_area_expanded(app_pc original_start, app_pc original_end, app_pc new_start, app_pc new_end, bool is_dynamo_area) {
    module_location_t *module;

    if (!CROWD_SAFE_MODULE_LOG())
        return;

    if (!is_dynamo_area) {
        MODULE_LOCK
        module = module_vector_overlap_search(module_list, original_start, original_end);
        MODULE_UNLOCK
        if (module == NULL) {
            module = &unknown_module;
        } else {
            subsume_overlapping_modules(module, new_start, module->start_pc-1, __FUNCTION__);
            subsume_overlapping_modules(module, module->end_pc+1, new_end, __FUNCTION__);
        }

        if (module->type == module_type_anonymous)
            expand_anonymous_module(module, new_start, new_end);
    }
}

bool
assign_black_box_singleton(module_location_t *module, bb_hash_t entry_hash) {
    uint i, count;
    bool new_singleton = false;
    ASSERT(module->type == module_type_anonymous);

    MODULE_LOCK
    count = *black_box_singleton_count;
    for (i = 0; i < count; i++) {
        if (black_box_singleton_list[i] == entry_hash)
            break;
    }

    if (i == count) {
        ASSERT(i < MAX_BLACK_BOX_SINGLETONS);

        CS_LOG("Assigning black box singleton #%d to entry hash 0x%llx\n", i, entry_hash);

        new_singleton = true;
        black_box_singleton_list[i] = entry_hash;
        (*black_box_singleton_count)++;

        if (i >= MAX_BLACK_BOX_SINGLETONS)
            CS_ERR("Too many black box singletons: %d!\n", i);
    }
    module->black_box_singleton = int2p(i + BLACK_BOX_SINGLETON_FAKE_PC_OFFSET);
    MODULE_UNLOCK

    return new_singleton;
}

void
memory_released(dcontext_t *dcontext, app_pc start, app_pc end) {
    if (!CROWD_SAFE_MODULE_LOG())
        return;

    MODULE_LOCK {
    module_location_t *module = module_vector_overlap_search(module_list, start, end);
    MODULE_UNLOCK

    if (module != NULL) {
        if (start > module->start_pc) {
            if (end < module->end_pc) {
                CS_DET("Anonymous module (%s ["PX"-"PX"]) memory released: internal chunk ["PX"-"PX"]\n",
                    module->module_name, module->start_pc, module->end_pc, start, end);
            } else {
                CS_DET("Anonymous module (%s ["PX"-"PX"]) memory released: tail chunk ["PX"-"PX"]\n",
                    module->module_name, module->start_pc, module->end_pc, start, end);
            }
        } else if (end < module->end_pc) {
            CS_DET("Anonymous module (%s ["PX"-"PX"]) memory released: head chunk ["PX"-"PX"]\n",
                module->module_name, module->start_pc, module->end_pc, start, end);
        } else {
            unregister_module(module);
            CS_DET("Unloading anonymous module (%s ["PX" - "PX"]) for memory release "PX" - "PX"\n",
                module->module_name, module->start_pc, module->end_pc, start, end);
        }
    }}

    CS_DET("DMP| Memory released ("PX"-"PX")\n", start, end);
    remove_shadow_pages(dcontext, start, end-start);
}

void
add_shadow_pages(dcontext_t *dcontext, app_pc base, size_t size, bool safe_to_read) {
    if (CROWD_SAFE_BB_GRAPH()) {
        uint i, count = size >> 0xc;
        for (i = 0; i < count; i++)
            add_shadow_page(dcontext, base + (i * 0x1000), safe_to_read);
    }
}

void
remove_shadow_pages(dcontext_t *dcontext, app_pc base, size_t size) {
    if (CROWD_SAFE_BB_GRAPH()) {
        uint i, count = size >> 0xc;
        for (i = 0; i < count; i++)
            remove_shadow_page(dcontext, base + (i * 0x1000));
    }
}

bool
observe_shadow_page_entry(module_location_t *from_module, app_pc target_tag) {
    module_location_t *target_module;

    target_module = get_module_for_address(target_tag);
    if (target_module->type == module_type_image)
        return false;
    if (IS_BLACK_BOX(target_module) && IS_BLACK_BOX(from_module) && // black box may always write to itself
            (target_module->black_box_entry == from_module->black_box_entry))
        return true;

    MODULE_LOCK {
        uint i;
        shadow_page_t *page = shadow_page_table_search(shadow_page_table, target_tag);
        MODULE_UNLOCK

        if (page == NULL) {
            CS_WARN("DMP: No shadow page for entry from %s to "PX"\n", from_module->module_name, target_tag);
            return false;
        }

        for (i = 0; i < page->pending_edges->entries; i++) {
            pending_gencode_edge_t *pending_edge = page->pending_edges->array[i];
            if ((pending_edge->from_module == from_module) && (pending_edge->edge_type == gencode_perm_edge)) {
                return true;
            }
        }

        return false;
    }
}

void
observe_shadow_page_write(dcontext_t *dcontext, module_location_t *writing_module,
                          app_pc writer_tag, app_pc pc, size_t size)
{
    module_location_t *written_module;
    executable_write_t *previous_write, write = { pc, pc + size, 0 };

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    written_module = get_module_for_address(pc);
    if (written_module->type == module_type_image)
        return;

    // 1. trim/toss any overlapping entries
    // 2. add new entry

    MODULE_LOCK
    while (true) {
        previous_write = executable_write_list_overlap_search(executable_write_list, write.start, write.end);
        if (previous_write == NULL)
            break;

        if (previous_write->start < write.start) {
            app_pc previous_end = previous_write->end;

            previous_write->end = write.start; // N.B.: relocate the existing one before (potentially) adding a split
            if (previous_write->end > write.end) {
                executable_write_t split = { write.end, previous_end, 0 };
                copy_appstack(&split, previous_write);
                executable_write_list_insert(executable_write_list, split, split.start);
            }
        } else if (previous_write->end > write.end) {
            previous_write->start = write.end;
        } else {
            executable_write_list_remove(executable_write_list, previous_write->start);
        }
    }
    take_write_stack_snapshot(dcontext, &write, writer_tag);
    executable_write_list_insert(executable_write_list, write, write.start);
    MODULE_UNLOCK
}

void
write_gencode_edges(dcontext_t *dcontext, crowd_safe_thread_local_t *cstl, app_pc physical_to, app_pc logical_to,
    bb_state_t *to_state, module_location_t *to_module)
{
    uint i;
    shadow_page_t *page;
    bb_state_t *from_state;
    executable_write_t *write;
    bb_hash_t to_entry_hash = NULL;
    bool is_black_box = to_module->black_box_singleton != NULL;

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    MODULE_LOCK
    page = shadow_page_table_search(shadow_page_table, physical_to);
    MODULE_UNLOCK

    if (page == NULL) {
        CS_WARN("DMP: No shadow page for entry to dynamic unit at "PX"\n", physical_to);
        return;
    }

    if (is_black_box) {
        ptr_uint_t black_box_list_id = (ptr_uint_t) (to_module->black_box_singleton - BLACK_BOX_SINGLETON_FAKE_PC_OFFSET);
        to_entry_hash = black_box_singleton_list[black_box_list_id];
    }

    MODULE_LOCK
    for (i = 0; i < page->pending_edges->entries; i++) {
        uint j;
        bool duplicate = false;
        pending_gencode_edge_t *pending_edge = page->pending_edges->array[i];
        module_location_t *from_module = get_module_for_address(pending_edge->from);

        for (j = 0; j < to_module->gencode_from_tags->entries; j++) {
            if (to_module->gencode_from_tags->array[j] == pending_edge->from) {
                duplicate = true;
                break;
            }
        }
        // cs-todo: would be nice to have invocations, but only for unverified edges--how to tell from here?
        if (duplicate) {
            if (is_black_box && from_module->black_box_entry == to_entry_hash)
                break;
        } else {
            drvector_append(to_module->gencode_from_tags, pending_edge->from);
        }

        MODULE_UNLOCK

        from_state = get_bb_state(pending_edge->from);
        if (from_state == NULL) {
            CS_LOG("DMP| Gencode edge %s("PX") to "PX"/"PX" type %d pending\n",
                pending_edge->from_module->module_name, MODULAR_PC(pending_edge->from_module, pending_edge->from),
                physical_to, logical_to, pending_edge->edge_type);
            add_pending_edge(logical_to, pending_edge->from, default_edge_ordinal(pending_edge->edge_type),
                pending_edge->edge_type, to_module, pending_edge->from_module, true);
        } else {
            CS_LOG("DMP| Gencode edge %s("PX") -> "PX"/"PX" type %d directly written\n",
                pending_edge->from_module->module_name, MODULAR_PC(pending_edge->from_module, pending_edge->from),
                physical_to, logical_to, pending_edge->edge_type);
            write_link(dcontext, pending_edge->from, logical_to, from_state, to_state, pending_edge->from_module,
                to_module, default_edge_ordinal(pending_edge->edge_type), pending_edge->edge_type);
        }
        MODULE_LOCK

        if (is_black_box && from_module->black_box_entry == to_entry_hash)
            break;
    }

    while (true) {
        write = executable_write_list_overlap_search(executable_write_list, physical_to, physical_to + to_state->size);
        if (write == NULL)
            break;

        MODULE_UNLOCK
        for (i = 0; i < write->frame_count; i++) {
            from_state = get_bb_state(write->frames[i].return_address);
            if (from_state == NULL) {
                add_pending_edge(logical_to, write->frames[i].return_address, default_edge_ordinal(gencode_write_edge),
                                 gencode_write_edge, to_module, write->frames[i].module, true);
            } else {
                write_link(dcontext, write->frames[i].return_address, logical_to, from_state, to_state,
                           write->frames[i].module, to_module, default_edge_ordinal(gencode_write_edge),
                           gencode_write_edge);
            }
        }
        MODULE_LOCK

        executable_write_list_remove(executable_write_list, write->start); // N.B.: remove after using the entry
    }
    MODULE_UNLOCK
}

void
add_export_hash(app_pc absolute_address, uint relative_address,
                function_export_t export, bool write_xhash)
{
    export_hashtable_add(export_hashes, absolute_address, export);

    if (write_xhash)
        write_cross_module_hash(relative_address, export);
}

bool
register_xhash(char *xhash_name) {
    if (hashtable_lookup(xhash_table, xhash_name) != NULL)
        return false;

    hashtable_add(xhash_table, xhash_name, XHASH_WRITTEN_MARKER);
    return true;
}

#ifdef GENCODE_CHUNK_STUDY
void
notify_shadow_page_decode(app_pc tag) {
    shadow_page_t *page;
    MODULE_LOCK
    page = shadow_page_table_search(shadow_page_table, tag);
    if (page != NULL) {
        uint chunk_index = CHUNK_INDEX(tag);

        if (page->ever_flushed && !page->ever_visited_after_flush[chunk_index]) {
            page->ever_visited_after_flush[chunk_index] = true;
            flush_report_counter->count++;
            if (is_report_threshold(&flush_report_counter->mask, flush_report_counter->count))
                CS_LOG("Total chunks visited after any flush: %d\n", flush_report_counter->count);
        }

        if (page->chunk_flushed[chunk_index]) {
            bb_hash_t hash = hash_chunk(((uint64*)page->start_pc) + (CHUNK_WORDS * chunk_index));
            bb_hash_t *found = chunk_hash_vector_search(&page->chunks[chunk_index], hash);
            if (found == NULL) {
                chunk_hash_vector_insert(&page->chunks[chunk_index], hash, hash);

                valid_flush_report->count++;
                if (is_report_threshold(&valid_flush_report->mask, valid_flush_report->count))
                    CS_LOG("Total chunks changed after flush: %d\n", valid_flush_report->count);
            } else {
                if (page->last_chunk_hash[chunk_index] != hash) {
                    rotation_report->count++;
                    if (is_report_threshold(&rotation_report->mask, rotation_report->count))
                        CS_LOG("Total reverted chunks: %d\n", rotation_report->count);
                }

                if (page->chunks[chunk_index].entries == 1) {
                    redundant_flush_report_singleton->count++;
                    if (is_report_threshold(&redundant_flush_report_singleton->mask, redundant_flush_report_singleton->count))
                        CS_LOG("Total chunks unchanged after flush (singleton): %d\n", redundant_flush_report_singleton->count);
                } else {
                    redundant_flush_report_multiple->count++;
                    if (is_report_threshold(&redundant_flush_report_multiple->mask, redundant_flush_report_multiple->count))
                        CS_LOG("Total chunks unchanged after flush (multiple): %d\n", redundant_flush_report_multiple->count);
                }
            }
            page->last_chunk_hash[chunk_index] = hash;
            page->chunk_flushed[chunk_index] = false;
        }
    }
    MODULE_UNLOCK
}

void
notify_flush(app_pc base, size_t size) {
    uint i, j, page_count = (size >> 0xc);

    if (!CROWD_SAFE_BB_GRAPH())
        return;

    MODULE_LOCK
    for (i = 0; i < page_count; i++) {
        shadow_page_t *page = shadow_page_table_search(shadow_page_table, base + (i * 0x1000));
        if (page != NULL)  {
            page->ever_flushed = true;
            for (j = 0; j < CHUNKS_PER_PAGE; j++)
                page->chunk_flushed[j] = true;
            //update_shadow_page_chunks(page);
        }
    }
    MODULE_UNLOCK
}
#endif

bool
is_modular_pc(const char *target_module, app_pc target_pc, app_pc lookup_pc) {
    module_location_t *module = get_module_for_address(lookup_pc);

    return (module != NULL && strcmp(module->module_name, target_module) == 0 &&
            MODULAR_PC(module, lookup_pc) == target_pc);
}

#ifdef UNIX
void
register_plt_trampolines() {
    os_privmod_data_t opd;
    app_pc trampoline_entry;
    app_pc plt_start, plt_end;
    module_iterator_t *mi;
    bool relocated = true;
    int entry_count;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    mi = module_iterator_start();
    while (module_iterator_hasnext(mi)) {
        module_area_t *ma = module_iterator_next(mi);
        memset(&opd, 0, sizeof(opd));
        module_get_os_privmod_data(ma->start, ma->end - ma->start, relocated, &opd);
        plt_start = (app_pc)0xffffffffffffffffULL;
        plt_end = (app_pc)0x0ULL;
        entry_count = 0;

        ELF_RELA_TYPE *start = (ELF_RELA_TYPE *)opd.jmprel;
        ELF_RELA_TYPE *end = (ELF_RELA_TYPE *)(opd.jmprel + opd.pltrelsz);
        ELF_RELA_TYPE *rela;
        for (rela = start; rela < end; rela++) {
            trampoline_entry = (app_pc)(opd.load_delta + rela->r_offset);
            if (trampoline_entry <  plt_start)
                plt_start = trampoline_entry;
            if (trampoline_entry >= plt_end)
                plt_end = trampoline_entry + trampoline_size;

            uint r_type = (uint)ELF_R_TYPE(rela->r_info);
            if (r_type == ELF_R_JUMP_SLOT) {
                hashtable_add(plt_stubs, trampoline_entry, &plt_stub_token);
                entry_count++;
            }
        }

        if (plt_end > 0x0ULL)
            CS_LOG("M: %s .plt ["PX" - "PX"] (%d entries)\n", ma->full_path, plt_start, plt_end, entry_count);
    }
    module_iterator_stop(mi);
}
#endif

void
destroy_module_observer() {
    uint i;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    drsym_exit();

    for (i = 0; i < module_list->entries; i++)
        free_module_location(module_list->array[i]);
    module_vector_delete(module_list);
    dr_global_free(module_list, sizeof(module_vector_t));

    dr_global_free(module_count, sizeof(uint));

    export_hashtable_delete(export_hashes);
    dr_global_free(export_hashes, sizeof(export_hashtable_t));

    if (CROWD_SAFE_RECORD_XHASH()) {
        hashtable_delete(xhash_table);
        dr_global_free(xhash_table, sizeof(hashtable_t));
    }

    dr_global_free(anonymous_module_metadata, sizeof(anonymous_module_metadata_t));

    if (CROWD_SAFE_BB_GRAPH()) {
        shadow_page_table_delete(shadow_page_table);
        dr_global_free(shadow_page_table, sizeof(shadow_page_table_t));
    }

    dr_global_free(black_box_singleton_list, MAX_BLACK_BOX_SINGLETONS * sizeof(bb_hash_t));
    dr_global_free(black_box_singleton_count, sizeof(uint));

    dr_global_free(image_instance_index, sizeof(ushort));

#ifdef GENCODE_CHUNK_STUDY
    dr_global_free(redundant_flush_report_singleton, sizeof(chunk_change_t));
    dr_global_free(redundant_flush_report_multiple, sizeof(chunk_change_t));
    dr_global_free(valid_flush_report, sizeof(chunk_change_t));
    dr_global_free(flush_report_counter, sizeof(chunk_change_t));
    dr_global_free(rotation_report, sizeof(chunk_change_t));
#endif
}

/**** Private Functions ****/

#define MAX_APP_STACK_FRAMES 0x20

static inline void
add_shadow_page(dcontext_t *dcontext, app_pc base, bool safe_to_read) {
    priv_mcontext_t *mc = get_mcontext(dcontext);
    drvector_t *pending_edges = NULL;
    shadow_page_t *page = NULL;
    stack_frame_t appstack[MAX_APP_STACK_FRAMES];
    uint f, frame_count;

    if (mc == NULL) {
        pending_edges = CS_ALLOC(sizeof(drvector_t));
        drvector_init(pending_edges, 8U, false, NULL);
    } else {
        module_location_t *last_module = NULL;

        MODULE_LOCK
        page = shadow_page_table_search(shadow_page_table, base);
        MODULE_UNLOCK

        if (page != NULL) {
            if (page->executable) {
                CS_DET("DMP: Attempt to add a shadow page at "PX", which is already executable\n", base);
            } else {
                page->executable = true;
            }

            pending_edges = page->pending_edges;
        } else {
            pending_edges = CS_ALLOC(sizeof(drvector_t));
            drvector_init(pending_edges, 8U, false, NULL);

            CS_DET("DMP| Adding shadow page "PX"; stack modules:\n", base);
        }

        frame_count = get_app_stacktrace(mc, MAX_APP_STACK_FRAMES, appstack);
        for (f = 0; f < frame_count; f++) {
            pending_gencode_edge_t *pending_edge = CS_ALLOC(sizeof(pending_gencode_edge_t));

            CS_DET("\t"PX" %s\n", (app_pc)pc, appstack[f].module_name);

            pending_edge->from = appstack[f].return_address;
            pending_edge->from_module = appstack[f].module;
            pending_edge->edge_type = gencode_perm_edge;
            drvector_append(pending_edges, pending_edge);
        }
    }

    if (page == NULL) {
        page = CS_ALLOC(sizeof(shadow_page_t));
        page->start_pc = base;
        page->pending_edges = pending_edges;
        page->executable = true;

#ifdef GENCODE_CHUNK_STUDY
        {
            uint i;
            page->ever_flushed = false;
            for (i = 0; i < CHUNKS_PER_PAGE; i++) {
                chunk_hash_vector_init(&page->chunks[i], 8U, false, NULL, compare_hashes);
                page->last_chunk_hash[i] = 0ULL;
                page->chunk_flushed[i] = false;
                page->ever_visited_after_flush[i] = false;
            }
        }
#endif

        MODULE_LOCK
        CS_DET("Adding shadow page "PX"\n", page->start_pc);
        shadow_page_table_insert(shadow_page_table, page, page->start_pc);
        MODULE_UNLOCK
    }
}

static inline void
remove_shadow_page(dcontext_t *dcontext, app_pc base) {
    shadow_page_t *page;

    MODULE_LOCK
    page = shadow_page_table_search(shadow_page_table, base);

    if (page == NULL) {
        CS_DET("Page "PX" is released, but it wasn't a shadow page.\n", base);
        MODULE_UNLOCK
        return;
    }

    page->executable = false;
    MODULE_UNLOCK
}

static uint
get_app_stacktrace(priv_mcontext_t *mc, uint max_frames, stack_frame_t *frames)
{
    ptr_uint_t *pc = (ptr_uint_t *) (app_pc) mc->xbp;
    module_location_t *frame_module;
    uint f = 0;

    while (pc != NULL && is_readable_without_exception_query_os((byte *)pc, 8)) {
        frames[f].return_address = (app_pc) *(pc+1); // N.B.: using `frames[f]` as scratch at first
        if (frames[f].return_address != 0) {
            frame_module = get_module_for_address(frames[f].return_address);
            // take the top frame for each sequence of consecutive frames in the same module
            if (f == 0 || frame_module != frames[f-1].module) {
                frames[f].module = frame_module;
                if (++f == max_frames)
                    break;
            }
        }
        pc = (ptr_uint_t *) *pc;
    }

    return f;
}

static void
copy_appstack(executable_write_t *dst, executable_write_t *src)
{
    size_t size = sizeof(stack_frame_t) * src->frame_count;

    dst->frame_count = src->frame_count;
    dst->frames = CS_ALLOC(size);
    memcpy(dst->frames, src->frames, size);
}

static void
take_write_stack_snapshot(dcontext_t *dcontext, executable_write_t *write, app_pc writer_tag)
{
    priv_mcontext_t *mc = get_mcontext(dcontext);
    stack_frame_t appstack[MAX_APP_STACK_FRAMES];
    uint i, frame_count = MAX(1, get_app_stacktrace(mc, MAX_APP_STACK_FRAMES, appstack));

    write->frame_count = frame_count;
    write->frames = CS_ALLOC(sizeof(stack_frame_t) * write->frame_count);
    write->frames[0].writer_tag = writer_tag;
    write->frames[0].module = get_module_for_address(writer_tag);

    for (i = 1; i < frame_count; i++) {
        write->frames[i].return_address = appstack[i].return_address;
        write->frames[i].module = appstack[i].module;
    }
}

#ifdef GENCODE_CHUNK_STUDY
static inline void
update_shadow_page_chunks(shadow_page_t *page) {
    bb_hash_t hash;
    uint i;
    uint64 *code = (uint64*)page->start_pc;

    for (i = 0; i < CHUNKS_PER_PAGE; i++, code += CHUNK_WORDS) {
        page->chunk_flushed[i] = true;
        hash = hash_chunk(code);
        if (chunk_hash_vector_search(&page->chunks[i], hash) == 0ULL)
            chunk_hash_vector_insert(&page->chunks[i], hash, hash);
    }
}

static inline bb_hash_t
hash_chunk(uint64 *code) {
    bb_hash_t hash = 0ULL;
    uint64 *chunk_end = (code + CHUNK_WORDS);
    for (; code < chunk_end; code++)
        hash = hash ^ (hash << 5) ^ *code;

    return hash;
}
#endif

#ifdef WINDOWS
// cs-todo: is this different for x64?
static inline void
load_relocations(module_location_t *location, const char *module_path) {
    byte *signature;
    ushort optional_header_size;
    byte* section_table;
    bool found_relocations = false, parse_relocations = false;
    relocation_table_t *relocation_table;
    relocation_target_table_t *all_relocation_targets = NULL;
    ushort *relocation_table_index, *relocation_table_end;
    file_t relocation_file = INVALID_FILE;
    char relocation_file_path[256] = {0};
    extern const char *monitor_dataset_dir;

    signature = (byte*)((uint)location->start_pc + *((short*)(location->start_pc + 0x3c)));
    if (!CHECK_SIGNATURE(signature)) { // cs-todo: omit operands in this case
        CS_WARN("module %s is not in PE format! Signature is [0x%02x, 0x%02x, 0x%02x, 0x%02x]\n",
            location->module_name, *signature, *(signature+1), *(signature+2), *(signature+3));
        return;
    }

    if (RELOCATIONS_STRIPPED(signature)) {
        CS_WARN("relocations are stripped from module %s\n", location->module_name);
        return; // OS cannot rebase it, so no need for action in this case
    }

    optional_header_size = *(ushort*)(signature + 0x14);
    section_table = (byte*)((uint)signature + 0x18 + optional_header_size);
    while (true) {
        if (!IS_IGNORABLE_SECTION(section_table)) {
            if (!IS_SECTION(section_table))
                break;
            if (IS_RELOCATION_SECTION(section_table)) {
                found_relocations = true;
                break;
            }
        }
        section_table += 0x28;
    }

    if (!found_relocations) {
        CS_WARN("REL| No relocations for module %s\n", location->module_name);
        return;
    }

    relocation_table_index = (ushort*)(location->start_pc + *(uint*)((uint)section_table + 0xc));
    relocation_table_end = (ushort*)(p2int(relocation_table_index) + *(uint*)((uint)section_table + 0x8));

    CS_DET("REL| Loading relocations for module %s: "PX"-"PX"\n", location->module_name, relocation_table_index, relocation_table_end);

    relocation_table = CS_ALLOC(sizeof(relocation_table_t));
    relocation_table_init(relocation_table, 0x20, false, NULL, compare_relocation_page);

    if (CROWD_SAFE_BB_GRAPH()) {
        location->relocation_targets = CS_ALLOC(sizeof(relocation_target_table_t));
        relocation_target_table_init_ex(
            location->relocation_targets,
            KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            NULL,
            NULL, /* no custom hashing */
            NULL);

        strcat(relocation_file_path, monitor_dataset_dir);
        strcat(relocation_file_path, location->module_name);
        strcat(relocation_file_path, ".relocations.dat");
        relocation_file = dr_open_file(relocation_file_path, DR_FILE_READ);
        parse_relocations = (relocation_file == INVALID_FILE);
        if (parse_relocations) {
            CS_WARN("Failed to open relocation file read-only: %s\n", relocation_file_path);
            all_relocation_targets = CS_ALLOC(sizeof(relocation_target_table_t));
            relocation_target_table_init_ex(
                all_relocation_targets,
                KEY_SIZE,
                HASH_INTPTR,
                false,
                false,
                NULL,
                NULL, /* no custom hashing */
                NULL);
        } else {
            uint64 relocation_file_size;
            uint i, relocation_entry_count;
            size_t relocation_array_size;
            uint *relocation_array;

            dr_file_size(relocation_file, &relocation_file_size);
            if (relocation_file_size > 0ULL) {
                relocation_entry_count = (uint)(relocation_file_size / 4);
                relocation_array_size = (size_t) relocation_file_size;
                relocation_array = (uint *)dr_map_file(relocation_file, &relocation_array_size, 0ULL, PC(0), DR_MEMPROT_READ, 0UL);
                for (i = 0; i < relocation_entry_count; i++) {
                    relocation_target_table_add(location->relocation_targets, p2int(location->start_pc + relocation_array[i]), 1);
                }

                CS_LOG("Stuffed %d relocation entries in the hashtable from %s\n", relocation_entry_count, relocation_file_path);

                dr_unmap_file((void *) relocation_array, relocation_array_size);
            }
            dr_close_file(relocation_file);
        }
    } else {
        location->relocation_targets = NULL;
    }

    while (relocation_table_index < relocation_table_end) {
        app_pc page_start = int2p(*(uint*)relocation_table_index);
        relocation_table_page_t relocation_page = { page_start, NULL };

        if (page_start == NULL) {
            CS_ERR("REL: Failed to correctly read the length of a %s relocation table section. Terminating "PX" bytes before end.\n",
                location->module_name, (relocation_table_end - relocation_table_index));
            break;
        }

        relocation_table_index += 2;
        relocation_page.relocations = CS_ALLOC(sizeof(relocation_vector_t));
        memset(relocation_page.relocations, 0, sizeof(relocation_vector_t));
        relocation_page.relocations->entries = ((*(uint*)relocation_table_index - 8U) >> 1);
        relocation_table_index += 2;
        relocation_page.relocations->array = relocation_table_index;
        relocation_page.relocations->comparator = compare_relocation_entry_with_page_offset;
        relocation_table_insert(relocation_table, relocation_page, page_start);

        if (relocation_page.relocations->entries == 0) {
            CS_ERR("REL: Failed to correctly read the length of a %s relocation table section. Terminating "PX" bytes before end.\n",
                location->module_name, (relocation_table_end - relocation_table_index));
            break;
        }

        CS_DET("REL| Loading relocations for module %s: relative page "PX" with %d entries at "PX"\n",
            location->module_name, page_start, relocation_page.relocations->entries, relocation_table_index-4);

        relocation_table_index += relocation_page.relocations->entries;

        if (parse_relocations) {
            uint i;
            relocation_entry_t relocation;
            ptr_uint_t *absolute_operand_address;
            ptr_uint_t operand;
            for (i = 0; i < relocation_page.relocations->entries; i++) {
                relocation = relocation_page.relocations->array[i];
                if ((relocation & 0xf000U) != 0x3000U)
                    continue;
                absolute_operand_address = (ptr_uint_t *)(p2int(location->start_pc) + p2int(page_start) + (relocation & 0xfff));
                operand = *absolute_operand_address;

                relocation_target_table_add(all_relocation_targets, operand, 1);
            }
        }
    }

    if (parse_relocations) {
        relocation_file = dr_open_file(relocation_file_path, DR_FILE_WRITE_REQUIRE_NEW);
        if (relocation_file == INVALID_FILE || relocation_file == NULL) {
            CS_WARN("Failed to open new relocation file %s\n", relocation_file_path);
        }
    }
    /*

            relocation_file_path[0] = '\0';
            strcat(relocation_file_path, "C:\\Users\\minotaur\\AppData\\LocalLow\\Adobe\\Acrobat\\11.0\\foo.txt");
            //strcat(relocation_file_path, location->module_name);
            //strcat(relocation_file_path, ".relocations.dat");
            //relocation_file = dr_open_file(relocation_file_path, DR_FILE_WRITE_REQUIRE_NEW);
            relocation_file = dr_open_file(relocation_file_path, DR_FILE_READ);
            if (relocation_file == INVALID_FILE || relocation_file == NULL) {
                CS_WARN("Failed to open read-only: %s\n", relocation_file_path);
            } else {
                CS_WARN("But I can open read-only %s\n", relocation_file_path);
            }
            / *
            if (relocation_file == INVALID_FILE || relocation_file == NULL) {
                //CS_WARN("Failed to open new relocation file %s too\n", relocation_file_path);
                relocation_file_path[strlen(monitor_dataset_dir)] = '\0';
                strcat(relocation_file_path, "ntdll.dll.relocations.dat");
                relocation_file = dr_open_file(relocation_file_path, DR_FILE_READ);
                if (relocation_file == INVALID_FILE || relocation_file == NULL) {
                    CS_WARN("Failed to open an existing relocation file %s read-only\n", relocation_file_path);
                } else {
                    CS_WARN("But I can open an existing relocation file %s read-only\n", relocation_file_path);
                }
                relocation_file = NULL;
            }
            * /
        }
    }
    */

    if (parse_relocations) { // && relocation_file != INVALID_FILE && relocation_file != NULL) {
        uint i, j, prot;
        relocation_entry_t relocation;
        ptr_uint_t *absolute_operand_address;
        ptr_uint_t operand, operand_target, relative_operand;
        module_location_t *target_module;

        for (i = 0; i < relocation_table->entries; i++) {
            relocation_table_page_t relocation_page = relocation_table->array[i];
            for (j = 0; j < relocation_page.relocations->entries; j++) {
                relocation = relocation_page.relocations->array[j];
                if ((relocation & 0xf000U) != 0x3000U)
                    continue;
                absolute_operand_address = (ptr_uint_t *)(p2int(location->start_pc) + p2int(relocation_page.page_base) + (relocation & 0xfff));
                operand = *absolute_operand_address;
                relative_operand = operand - p2int(location->start_pc);
                if (!safe_read((ptr_uint_t *)operand, sizeof(ptr_uint_t), &operand_target)) {
                    CS_DET("Relocation: skipping "PX"<%s("PX")> because it is not readable.\n",
                           operand, location->module_name, relative_operand);
                    continue;
                }
                if (relocation_target_table_lookup_value(all_relocation_targets, operand_target) != 0U) {
                    CS_DET("Relocation: skipping "PX"<%s("PX")> because it points to a relocation slot.\n",
                           operand, location->module_name, relative_operand);
                    continue;
                }
                if (!get_memory_info((app_pc) operand, NULL, NULL, &prot)) {
                    CS_WARN("Failed to query memory protection of operand target "PX"\n");
                    continue;
                } else if (TEST(MEMPROT_WRITE, prot) || !TEST(MEMPROT_EXEC, prot)) {
                    CS_DET("Relocation: skipping "PX"<%s("PX")> because it is writable or not executable.\n",
                           operand, location->module_name, relative_operand);
                    continue;
                }

                if (operand_target == 0 || operand_target >= 0xffffff00U || operand_target <= 0xff) {
                    CS_DET("Relocation: skipping "PX" because it is a small or large uint.\n",
                           operand, location->module_name, relative_operand);
                    continue;
                }
                relocation_target_table_add(location->relocation_targets, operand, 1);
                dr_write_file(relocation_file, &relative_operand, sizeof(ptr_uint_t));

                target_module = get_module_for_address(int2p(operand_target));
                if (location == target_module) {
                    CS_DET("Relocation "PX" points to an internal non-relocation-entry "PX"\n",
                           operand, operand_target);
                } else {
                    CS_DET("Relocation "PX" points to an external non-relocation-entry "PX"\n",
                           operand, operand_target);
                }
            }
        }

        relocation_target_table_delete(all_relocation_targets);
        dr_global_free(all_relocation_targets, sizeof(relocation_target_table_t));

        dr_close_file(relocation_file);
    }

    location->relocation_table = (module_relocations_t*)relocation_table;

    if (*(uint*)relocation_table_index != 0)
        CS_WARN("REL: Found data at the end of the relocation table. Page offset would be "PX"\n",
            int2p(*(uint*)relocation_table_index));
}

static bool
symbol_iteration_callback(drsym_info_t *info, drsym_error_t status, void *data) {
    xhash_module_t *xhash = (xhash_module_t *) data;
    function_export_t internal_export; // = { hash, str }
    char symbol_id[256], symbol_name[256];
    app_pc symbol_pc = xhash->module->start_pc + info->start_offs;

    if (export_hashtable_lookup(export_hashes, symbol_pc) == NULL) { // ignore symbolic aliases
        print_callback_function_id(symbol_id, 256, xhash->module, info->start_offs);
        internal_export.hash = string_hash(symbol_id);

        dr_snprintf(symbol_name, 256, "%s!%s", xhash->module->module_name, info->name);
        internal_export.function_id = cs_strcpy(symbol_name);

        add_export_hash(symbol_pc, info->start_offs, internal_export, xhash->write_xhash);
    }

    return true;
}

static void
initialize_module_exports(module_location_t *module, const char *module_path) {
    uint i, exported_ordinal, function_id_base_length;
    xhash_module_t xhash_module = {0};
    app_pc exported_address;
    uint relative_address;
    size_t exports_size;
    char *exported_name;
    bb_hash_t hash;

    IMAGE_EXPORT_DIRECTORY *exports = get_module_exports_directory_common(
        module->start_pc, &exports_size _IF_NOT_X64(NULL));

    CS_LOG("initialize exports for %s\n", module->module_name);

    ASSERT(strlen(module->module_name) < MAX_MODULE_NAME_LENGTH);

    if (CROWD_SAFE_RECORD_XHASH() && module->type == module_type_image) {
        xhash_module.module = module;
        if (CROWD_SAFE_MONITOR())
            xhash_module.write_xhash = (module->monitor_data == NULL);
        else
            xhash_module.write_xhash = register_xhash_module(module);
    }

    if (exports == NULL) {
        char function_id[FUNCTION_ID_LENGTH];
        module_data_t *main = dr_get_main_module();
        if (main == NULL) {
            CS_WARN("Main module not found while initializing exports\n");
            return;
        }

        CS_LOG("Main module at "PX"; entry point "PX"???\n", main->start, main->entry_point); // cs-hack: winsock

        if (main->start != module->start_pc) {
            CS_WARN("Exports not found for module %s\n", module->module_name);
            return;
        }
        strcat(function_id, "!main"); // valid for the main entry point of any program
        hash = string_hash(function_id);
        hashcode_lock_acquire(); {
            function_export_t export = { hash, cs_strcpy(function_id) };
            export_hashtable_add(export_hashes, main->entry_point, export);
        }
        hashcode_lock_release();
    } else {
        char function_id_base[256] = {0};
        PULONG functions = (PULONG)(module->start_pc + exports->AddressOfFunctions);
        PUSHORT ordinals = (PUSHORT)(module->start_pc + exports->AddressOfNameOrdinals);
        PULONG fnames = (PULONG)(module->start_pc + exports->AddressOfNames);

        hashcode_lock_acquire();

        strncat(function_id_base, module->module_name, MAX_MODULE_NAME_LENGTH);
        strcat(function_id_base, "!");
        function_id_base_length = strlen(function_id_base);

        for (i = 0; i < exports->NumberOfNames; i++) {
            char function_id[FUNCTION_ID_LENGTH];

            strcpy(function_id, function_id_base);
            relative_address = functions[ordinals[i]];
            exported_address = int2p(module->start_pc + relative_address);
            exported_name = (char *)((uint)module->start_pc + fnames[i]);
            strncat(function_id, exported_name, 154); // "<to-module>!<function-name>"
            hash = string_hash(function_id);
            {
                function_export_t export = { hash, cs_strcpy(function_id) };
                add_export_hash(exported_address, relative_address, export, xhash_module.write_xhash);
            }
        }

        strcat(function_id_base, "@ordinal");
        function_id_base_length = strlen(function_id_base);
        for (i = 0; i < exports->NumberOfFunctions; i++) {
            relative_address = functions[i];
            exported_address = int2p(module->start_pc + relative_address);
            exported_ordinal = i+1;
            if ((p2int(exported_address) > p2int(exports)) && (p2int(exported_address) < p2int(exports + exports_size))) {
                exported_name = (char *)int2p(exported_address);
                // it's a redirect, what does it match?

                CS_DET("Found export redirect to %s in the noname section of module %s.\n", exported_name, module->module_name);
            } else if (export_hashtable_lookup(export_hashes, exported_address) == 0U) { // it's a noname ordinal
                char function_id[FUNCTION_ID_LENGTH];

                strcpy(function_id, function_id_base);

                // cs-todo: these may need to be identified as callbacks when not explicitly imported by ordinal

                // "<to-module>@ordinal(#)"
                dr_snprintf(function_id + function_id_base_length, 8, "(%d)", exported_ordinal);
                hash = string_hash(function_id);
                {
                    function_export_t export = { hash, cs_strcpy(function_id) };
                    add_export_hash(exported_address, relative_address, export, xhash_module.write_xhash);
                }

                CS_DET("Found export ordinal %d in the noname section of module %s.\n", exported_ordinal, module->module_name);
            }
        }
        hashcode_lock_release();
    }

    if (CROWD_SAFE_RECORD_XHASH() && module->type == module_type_image && drsym_module_has_symbols(module_path))
        drsym_enumerate_symbols_ex(module_path, symbol_iteration_callback, sizeof(drsym_info_t),
                                   &xhash_module, DRSYM_DEMANGLE_PDB_TEMPLATES);
}

static void
clear_module_exports(module_location_t *module) {
    size_t exports_size;
    IMAGE_EXPORT_DIRECTORY *exports = get_module_exports_directory_common(
        module->start_pc, &exports_size _IF_NOT_X64(NULL));

    assert_hashcode_lock();

    if (exports == NULL)
        return;

    {
        uint i;
        app_pc exported_address;
        PULONG functions = (PULONG)(module->start_pc + exports->AddressOfFunctions);
        PUSHORT ordinals = (PUSHORT)(module->start_pc + exports->AddressOfNameOrdinals);

        for (i = 0; i < exports->NumberOfNames; i++) {
            exported_address = int2p(module->start_pc + functions[ordinals[i]]);
            export_hashtable_remove(export_hashes, exported_address);
        }

        for (i = 0; i < exports->NumberOfFunctions; i++) {
            exported_address = int2p(module->start_pc + functions[i]);
            export_hashtable_remove(export_hashes, exported_address);
        }
    }
}

#ifdef CROWD_SAFE_DYNAMIC_IMPORTS
static void
find_get_proc_address(module_location_t *module) {
    size_t exports_size;
    IMAGE_EXPORT_DIRECTORY *exports;
    uint i;

    exports = get_module_exports_directory_common
        (module->start_pc, &exports_size _IF_NOT_X64(NULL));
    if (exports == NULL) {
        CS_WARN("No exports found for kernelbase.dll!\n");
    } else {
        PULONG functions = (PULONG)(module->start_pc + exports->AddressOfFunctions);
        PUSHORT ordinals = (PUSHORT)(module->start_pc + exports->AddressOfNameOrdinals);
        PULONG fnames = (PULONG)(module->start_pc + exports->AddressOfNames);

        for (i = 0; i < exports->NumberOfNames; i++) {
            if (!strcasecmp((char *)((ulong)module->start_pc + fnames[i]), "GetProcAddress")) {
                extern app_pc *kernel_base_get_proc_address;
                *kernel_base_get_proc_address = (app_pc)((ulong)module->start_pc + functions[ordinals[i]]);
                CS_LOG("Found kernelbase!GetProcAddress() at "PX".\n", *kernel_base_get_proc_address);
                return;
            }
        }

        CS_WARN("Could not find GetProcAddress() among the exports of kernelbase.dll.\n");
    }
}
#endif

#endif

static void
free_module_location(void *m) {
    uint i;
    module_location_t *module = (module_location_t*)m;
    relocation_table_t *relocation_table = (relocation_table_t*)module->relocation_table;
    relocation_target_table_t *relocation_targets = (relocation_target_table_t*)module->relocation_targets;

    CS_DET("Free module %s ("PX" - "PX")\n", module->module_name, module->start_pc, module->end_pc);

    if (module->gencode_from_tags != NULL) {
        drvector_delete(module->gencode_from_tags);
        dr_global_free(module->gencode_from_tags, sizeof(drvector_t));
    }

    free_monitor_module(module);

    if (relocation_table != NULL) {
        for (i = 0; i < relocation_table->entries; i++)
            dr_global_free(relocation_table->array[i].relocations, sizeof(relocation_vector_t));

        relocation_table_delete(relocation_table);
        dr_global_free(relocation_table, sizeof(relocation_table_t));
    }
    if (relocation_targets != NULL) {
        dr_global_free(relocation_targets, sizeof(relocation_target_table_t));
    }

    dr_global_free(module->module_name, strlen(module->module_name) + 1);
    dr_global_free(module, sizeof(module_location_t));
}

static void
free_shadow_page(void *p) {
    shadow_page_t *page = (shadow_page_t*)p;
    CS_DET("Free shadow page ("PX" - "PX")\n", module->start_pc, module->end_pc);

    if (page->pending_edges != NULL) {
        uint i;
        for (i = 0; i < page->pending_edges->entries; i++)
            dr_global_free(page->pending_edges->array[i], sizeof(pending_gencode_edge_t));

        drvector_delete(page->pending_edges);
        dr_global_free(page->pending_edges, sizeof(drvector_t));
    }
    dr_global_free(page, sizeof(shadow_page_t));
}

static void
free_executable_write(executable_write_t write) {
    dr_global_free(write.frames, sizeof(stack_frame_t) * write.frame_count);
}

/**** Private Functions ****/

static inline bool
is_syscall_trampoline_name(char *name) {
    return ((strlen(name) > 2) && (strmincmp(name, "Nt") == 0) && (name[2] >= 'A') && (name[2] <= 'Z'));
}

#ifdef UNIX
static inline void
resolve_pending_trampolines() {
    int i, j;
    trampoline_tracker *trampoline;
    trampoline_caller *caller;
    app_pc plt_target;
    uint64 target_delta;

    for (i = pending_trampolines->entries-1; i >= 0; i--) {
        trampoline = (trampoline_tracker*)drvector_get_entry(pending_trampolines, i);
        plt_target = *trampoline->plt_cell;
        target_delta = (uint64)(plt_target - trampoline->trampoline_entry);
        if (((target_delta < 0) || (target_delta > 0x10ULL)) &&
                (get_bb_hash(plt_target) != NULL)) {
                // check the hash because another thread could possibly resolve it
                // before this thread has reached the function entry, in which case
                // the `to` hashcode will not exist and the link can't be written
            trampoline->function_entry = plt_target;
            for (j = 0; j < trampoline->function_callers->entries; j++) {
                caller = drvector_get_entry(trampoline->function_callers, j);
                write_trampoline(trampoline, caller->call_site, caller->call_exit_ordinal,
                    caller->is_direct_link ? direct_edge : indirect_edge);
            }
            drvector_delete(trampoline->function_callers);
            dr_global_free(trampoline->function_callers, sizeof(drvector_t));
            trampoline->function_callers = NULL;
            drvector_remove(pending_trampolines, i);
        }
    }
}

static inline void
write_trampoline(trampoline_tracker *trampoline, app_pc function_caller,
        int caller_exit_ordinal, graph_edge_type edge_type)
{
    // Warning: this log entry is parsed by the PLT patch verification test!
    CS_LOG("T: patching new trampoline "PX" from caller "PX" to function "PX"\n",
        trampoline->trampoline_entry, function_caller, trampoline->function_entry);
    write_link(dcontext, function_caller, trampoline->function_entry, get_bb_state(function_caller),
        get_bb_state(trampoline->function_entry), (byte)caller_exit_ordinal, edge_type);
}
#endif

static inline void
create_anonymous_module(dcontext_t *dcontext, app_pc start, app_pc end, anonymous_module_metadata_t *metadata) {
    crowd_safe_thread_local_t *cstl;
    module_location_t *module = (module_location_t*)CS_ALLOC(sizeof(module_location_t));
    module->start_pc = start;
    module->end_pc = end;
    module->type = metadata->module_type;
    module->black_box_singleton = 0ULL;
    module->black_box_singleton_state = NULL;
    module->black_box_entry = 0ULL;
    module->black_box_exit = 0ULL;
    module->gencode_from_tags = CS_ALLOC(sizeof(drvector_t));
    drvector_init(module->gencode_from_tags, 0x10U, false, NULL);
    module->image_instance_id = 0;
    module->version = metadata->version_index++;
    module->checksum = 0;
    module->timestamp = 0;
    module->relocation_table = NULL;
    module->relocation_targets = NULL;

    module->module_name = (char*)CS_ALLOC(strlen(metadata->module_name) + 1);
    strcpy(module->module_name, metadata->module_name);

    get_monitor_module(module); // requires no lock

    if (dcontext != NULL) {
        cstl = GET_CSTL(dcontext);

        CS_DET("MBBE: Created anonymous module at "PX" - "PX". Last tag "PX".\n",
            start, end, GET_LAST_DECODED_TAG(cstl));
    }
    register_module(module, NULL);
}

static inline void
expand_anonymous_module(module_location_t *module, app_pc start, app_pc end) {
    MODULE_LOCK {
    app_pc new_start = min(module->start_pc, start);
    app_pc new_end = max(module->end_pc, end);
    bool changed = !((new_start == module->start_pc) && (new_end == module->end_pc));
    MODULE_UNLOCK

    if (changed) {
        print_module_unload(module);

        MODULE_LOCK
        CS_DET("Expanding module %s "PX"-"PX" to "PX"-"PX"\n",
            module->module_name, module->start_pc, module->end_pc, new_start, new_end);
        module->start_pc = new_start;
        module->end_pc = new_end;
        MODULE_UNLOCK

        print_module_load(module);
    }}
}

static inline void
subsume_overlapping_modules(module_location_t *module, app_pc region_start, app_pc region_end, char *caller) {
    module_location_t *overlap_module;
    uint counter = 0;
    if (region_start < region_end) {
        while (true) {
            MODULE_LOCK
            overlap_module = module_vector_overlap_search(module_list, region_start, region_end);
            MODULE_UNLOCK

            if (overlap_module == module) {
                CS_ERR("Overlap search failure from %s: found the subsuming module!\n", caller);
                overlap_module = NULL;
            }
            if ((overlap_module == NULL) || (++counter > 100)) //|| (overlap_module == last_overlap_module))
                break;

            //last_overlap_module = overlap_module;

            if (IS_BLACK_BOX(overlap_module)) {
                if (IS_BLACK_BOX(module)) {
                    if (module->black_box_entry != overlap_module->black_box_entry)
                        CS_ERR("Black box ("PX"-"PX") subsumes a different black box ("PX"-"PX")!\n",
                            module->start_pc, module->end_pc, overlap_module->start_pc, overlap_module->end_pc);
                } else {
                    hashcode_lock_acquire();
                    confine_to_black_box(module, /*NULL,*/ overlap_module->black_box_entry,
                        overlap_module->black_box_exit, "subsumption", overlap_module->start_pc);
                    hashcode_lock_release();
                }
            } else if (IS_BLACK_BOX(module)) {
                CS_WARN("Black box ("PX"-"PX") subsumes a white box ("PX"-"PX")!\n",
                    module->start_pc, module->end_pc, overlap_module->start_pc, overlap_module->end_pc);
            }

            if ((overlap_module->start_pc + 1) < region_start) {
                print_module_unload(overlap_module);

                MODULE_LOCK
                CS_DET("Contracting module %s "PX"-"PX" to "PX"-"PX"\n",
                    overlap_module->module_name, overlap_module->start_pc, overlap_module->end_pc,
                    overlap_module->start_pc, region_start);
                overlap_module->end_pc = region_start;
                MODULE_UNLOCK

                print_module_load(overlap_module);
            } else if ((overlap_module->end_pc - 1) > region_end) {
                print_module_unload(overlap_module);

                MODULE_LOCK
                CS_DET("Contracting module %s "PX"-"PX" to "PX"-"PX"\n",
                    overlap_module->module_name, overlap_module->start_pc, overlap_module->end_pc,
                    region_end, overlap_module->end_pc);
                overlap_module->start_pc = region_end;
                MODULE_UNLOCK

                print_module_load(overlap_module);
            } else {
                unregister_module(overlap_module);
            }
        }
    }
}

static void
register_module(module_location_t *module, const char *module_path) {
    MODULE_LOCK {
    bool replaced = module_vector_insert(module_list, module, module->start_pc);
    MODULE_UNLOCK

    if (replaced)
        CS_ERR("Registration of module %s replaced an existing module!\n", module->module_name);

    print_module_load(module);

#ifdef WINDOWS
    if (module->type == module_type_image) {
        // if (strcmp("advcodec.dll", module->module_name) != 0)
        load_relocations(module, module_path); // requires no lock

# ifdef CROWD_SAFE_DYNAMIC_IMPORTS
        if ((strlen(module->module_name) > 0) && !strmincmp(module->module_name, "kernelbase"))
            find_get_proc_address(module); // requires no lock
# endif
    }
#endif
}}

static inline void
unregister_module(module_location_t *module) {
    print_module_unload(module);

    CS_DET("Remove module %s ("PX" - "PX")\n", module->module_name, module->start_pc, module->end_pc);

    MODULE_LOCK
    if (module_vector_remove(module_list, module->start_pc) != module)
        CS_ERR("Failed to remove module %s from the list!\n", module->module_name);
    MODULE_UNLOCK

    free_module_location(module);
}

static inline void
print_module_load(module_location_t *module) {
    char module_id[256];
    MODULE_LOCK {
    app_pc start = module->start_pc;
    app_pc end = module->end_pc;
    MODULE_UNLOCK

    print_module_id(module_id, 256, module);
    hashcode_lock_acquire();
    print_module_entry("Loaded", module_id, start, end);
    hashcode_lock_release();
}}

static inline void
print_module_unload(module_location_t *module) {
    char module_id[256];
    MODULE_LOCK {
    app_pc start = module->start_pc;
    app_pc end = module->end_pc;
    MODULE_UNLOCK

    print_module_id(module_id, 256, module);
    hashcode_lock_acquire();
    print_module_entry("Unloaded", module_id, start, end);

    (*module_count)++;
    if ((module->type == module_type_anonymous) && (*module_count > 1000000)) { // baloney, something is spinning out
        CS_ERR("Too many dynamic modules, something is out of control. Exiting now.\n");
        notify_process_terminating(true); // bail now!
    }

    hashcode_lock_release();
}}

static int
compare_hashes(bb_hash_t first, bb_hash_t second) {
    uint64 delta = (first - second);
    if (delta < 0LL)
        return -1;
    else if (delta > 0LL)
        return 1;
    else
        return 0;
}

static int
compare_executable_write_with_pc(executable_write_t write, app_pc second) {
    ptr_uint_t first_int = p2int(write.start), second_int = p2int(second);

    if (first_int < second_int)
        return -1;
    else if (first_int > second_int)
        return 1;
    else
        return 0;
}

static int
compare_module_vs_tag(module_location_t *module, app_pc tag) {
    int comparison = (module->start_pc - tag);
    if ((comparison < 0) && (tag < module->end_pc))
        return 0;
    return comparison;
}

static int
compare_page_vs_tag(shadow_page_t *page, app_pc tag) {
    int comparison = (tag - page->start_pc);
    if ((comparison >= 0) && (comparison < 0x1000))
        return 0;
    return -comparison;
}

static int
compare_relocation_page(relocation_table_page_t relocation_page, app_pc page) {
    return p2int(relocation_page.page_base - page);
}

static int
compare_relocation_entry_with_page_offset(ushort relocation_entry, ushort page_offset) {
    if (((relocation_entry & 0xf000U) != 0x3000U) && ((relocation_entry & 0xfff) == 0))
        return 1;
    else
        return (relocation_entry & 0xfff) - page_offset;
}

static bool
register_xhash_module(module_location_t *module) {
    char module_id[256];

    print_module_id(module_id, 256, module);
    return register_xhash(module_id);
}

static void
free_function_export(function_export_t export) {
    dr_global_free(export.function_id, strlen(export.function_id)+1);
}
