#include "crowd_safe_util.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "basic_block_hashtable.h"
#include "crowd_safe_trace.h"
//#include "stacktrace.h"
//#include "../../core/x86/instrument.h"
//#include "../../core/utils.h"

#ifdef UNIX
# include <pthread.h>
#elif defined WINDOWS
# include <Windows.h>
#endif

/**** Public Fields ****/

void *hashcode_mutex; // only for access by inline functions in crowd_safe_util.h

char *monitor_dataset_path;

extern const char *monitor_dataset_dir;

/**** Private Fields ****/

static const char *CROWD_SAFE_HASHLOG_DIR = "CROWD_SAFE_HASHLOG_DIR";
static const char *CROWD_SAFE_DATASET_DIR = "CROWD_SAFE_DATASET_DIR";
#ifdef UNIX
static const char FILE_SEPARATOR_CHAR = '/';
static const char *FILE_SEPARATOR_STRING = "/";
static const char *DEFAULT_HASHLOG_DIRECTORY = "./";
static const char *DEFAULT_DATASET_DIRECTORY = "./";
#elif defined WINDOWS
static const char FILE_SEPARATOR_CHAR = '\\';
static const char *FILE_SEPARATOR_STRING = "\\";
static const char *DEFAULT_HASHLOG_DIRECTORY = "c:\\Users\\b\\AppData\\LocalLow\\hashlog";
static const char *DEFAULT_DATASET_DIRECTORY = "c:\\Users\\b\\AppData\\LocalLow\\hashlog\\monitor";
#endif

#define ENV_DYNAMORIO_HOME "DYNAMORIO_HOME"
#define BLACK_BOX_CONFIG_FILENAME "anonymous-blackbox-owners.cfg"
#define PROCESS_DATASET_MAP_FILENAME "process-dataset-map.cfg"

static char application_short_name[64] = {0};
static size_t application_short_name_length;

static char hashlog_dir[64] = {0};

/* tweaked for traces?
static const uint stack_spy_sysnums_x86[] = // { [0x1F..0]U, [0x3F..0x20]U, [0x5F..0x40]U, etc. }
    { 0xffffbfffU, 0xfffbffcfU, 0xffffffffU, 0xff6ffffbU, 0xfffe56ffU, 0xffffffffU, 0xcbffffffU, 0xb948d564U,
      0xffe7fb9cU, 0xffffffffU, 0xffffffffU, 0xffffffffU, 0x1ffcfU };
*/

static dr_time_t process_start_time;

void *log_mutex = NULL;

// [search tags]: monitored tracked observed system calls syscalls sysnums: this is where we choose the sysnums to monitor
typedef struct _stack_spy_sysnum_set_t {
    const uint x86[0xd];          // { [0x1F..0]U, [0x3F..0x20]U, [0x5F..0x40]U, etc. }
    const uint x86_netmon[0xd];
    const uint wow64[0xe];        // { [0x20..1]U, [0x40..0x21]U, [0x60..0x41]U, etc. }
    const uint wow64_netmon[0xe];
} stack_spy_sysnum_set_t;

static stack_spy_sysnum_set_t stack_spy_sysnum_sets = {
        { /*0x20*/ 0xffffbfffU, /*0x40*/ 0xfffbffcfU, /*0x60*/ 0xffffffffU, /*0x80*/ 0xff6ffffbU, /*0xA0*/ 0xfffe56ffU,
          /*0xC0*/ 0xffffffffU, /*0xE0*/ 0xcbffffffU, /*0x100*/ 0xb948d564U, /*0x120*/ 0xffe7fb9cU, /*0x140*/ 0xffffffffU,
          /*0x160*/ 0xffffffffU, /*0x180*/ 0xffffffffU, /*0x1A0*/ 0x1ff0fU }, // (or 0x1ffcfU) ?
        { /*0x20*/ 0xffffbfffU, /*0x40*/ 0xfffbffcfU, /*0x60*/ 0xffffffffU, /*0x80*/ 0xff6ffffbU, /*0xA0*/ 0xfffe56ffU,
          /*0xC0*/ 0xffffffffU, /*0xE0*/ 0xcbffffffU, /*0x100*/ 0xb948d564U, /*0x120*/ 0xffe7fb9cU, /*0x140*/ 0xffffffffU,
          /*0x160*/ 0xffffffffU, /*0x180*/ 0xffffffffU, /*0x1A0*/ 0x1ffefU },
        { /*0x20*/ 0x5f9043d8U, /*0x40*/ 0xf1e89bfdU, /*0x60*/ 0xff3ad7deU, /*0x80*/ 0x3ffffdffU, /*0xA0*/ 0xffffffffU,
          /*0xC0*/ 0xc3ffffffU, /*0xE0*/ 0xfcf801f7U, /*0x100*/ 0xfffdffffU, /*0x120*/ 0x00000fffU, /*0x140*/ 0xff3ee000U,
          /*0x160*/ 0xffffffffU, /*0x180*/ 0xffffffffU, /*0x1A0*/ 0x26ff67ffU, /*0x1C0*/ 0x3U },
        { /*0x20*/ 0x5fd043d9U, /*0x40*/ 0xf1e89bfdU, /*0x60*/ 0xffbad7deU, /*0x80*/ 0x3ffffdffU, /*0xA0*/ 0xffffffffU,
          /*0xC0*/ 0xc3ffffffU, /*0xE0*/ 0xfcf801f7U, /*0x100*/ 0xfffdffffU, /*0x120*/ 0x00000fffU, /*0x140*/ 0xff3ee000U,
          /*0x160*/ 0xffffffffU, /*0x180*/ 0xffffffffU, /*0x1A0*/ 0x26ff67ffU, /*0x1C0*/ 0x3U }
};
// cs-todo: only observe NtWaitForSingleObject when netmon is on (wow64: 0x1; x86: 0x187)
const uint *stack_spy_sysnums;
uint stack_spy_sysnum_offset;

//typedef struct _crowd_safe_util_metadata_t {
//} crowd_safe_util_metadata_t;

// crowd_safe_util_metadata_t *metadata;

#ifdef CROWD_SAFE_TRACK_MEMORY
typedef struct memory_allocation_t memory_allocation_t;
struct memory_allocation_t {
    app_pc address;
    size_t size;
    const char *file;
    const char *function;
    int line;
};

typedef struct memory_span_t memory_span_t;
struct memory_span_t {
    app_pc start;
    app_pc end;
};

static void*
memory_tracker_alloc(size_t size);

/* Template instantiation: memory_allocation_vector_t */
#define VECTOR_NAME_KEY memory_allocation_vector
#define VECTOR_ENTRY_TYPE memory_allocation_t*
#define VECTOR_ALLOCATOR memory_tracker_alloc
#define VECTOR_DEALLOCATOR dr_global_free
#define VECTOR_SORTED 1
#define VECTOR_COMPARISON_TYPE app_pc
#include "../drcontainers/drvector.h"

/* Template instantiation: memory_allocation_vector_t */
#define VECTOR_NAME_KEY memory_allocation_vector
#define VECTOR_ENTRY_TYPE memory_allocation_t*
#define VECTOR_ALLOCATOR memory_tracker_alloc
#define VECTOR_DEALLOCATOR dr_global_free
#define VECTOR_SORTED 1
#define VECTOR_COMPARISON_TYPE app_pc
#include "../drcontainers/drvectorx.h"

typedef struct memory_tracker_t memory_tracker_t;
struct memory_tracker_t {
    memory_allocation_vector_t allocations; // of memory_allocation_t
    bool is_dirty;
};

static bool memory_tracker_enabled;
static memory_tracker_t *memory_tracker;
#endif

/* Template instantiation: tag_vector_t */
#define VECTOR_NAME_KEY tag_vector
#define VECTOR_ENTRY_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvector.h"

/* Template instantiation: tag_vector_t */
#define VECTOR_NAME_KEY tag_vector
#define VECTOR_ENTRY_TYPE app_pc
#define VECTOR_ENTRY_INLINE 1
#include "../drcontainers/drvectorx.h"

typedef struct _call_stack_t {
    ushort id;
    uint64 hash;
    tag_vector_t tags;
} call_stack_t;

/* Template instantiation: call_stack_table_t */
#define HASHTABLE_NAME_KEY call_stack_table
#define HASHTABLE_KEY_TYPE uint64
#include "../drcontainers/drhashtable.h"

/* Template instantiation: call_stack_table_t */
#define HASHTABLE_NAME_KEY call_stack_table
#define HASHTABLE_KEY_TYPE uint64
#include "../drcontainers/drhashtablex.h"

static tag_vector_t *temp_tags;
static call_stack_table_t *call_stack_table;
static void *call_stack_mutex;

#define CALL_STACK_TABLE_KEY_SIZE 7
#define CALL_STACK_LOCK dr_mutex_lock(call_stack_mutex)
#define CALL_STACK_UNLOCK dr_mutex_unlock(call_stack_mutex)

#ifdef UNIX
static bool dr_takeover_complete;
static bool in_dr_takeover;
#endif

#define TRACKED_SYSNUM_COUNT 0x1a4

typedef struct syscall_frequency_t syscall_frequency_t;
struct syscall_frequency_t {
    uint count;
    report_mask_t mask;
};
static syscall_frequency_t *syscall_trackers[TRACKED_SYSNUM_COUNT];

static int parent_process_id;
bool verify_shadow_stack = true;
bool is_chrome_child = false;
static bool closed = false;

static const uint TRAMPOLINE_TABLE_KEY_SIZE = 10;

#ifdef CROWD_SAFE_TRACK_MEMORY
static void *alloc_mutex;
#endif

static void *shadow_stack_missing_frame_lock;
static hashtable_t *shadow_stack_missing_frame_table;
static void *SHADOW_STACK_MISSING_FRAME = (void *) "<missing>";
static const uint SHADOW_STACK_MISSING_FRAME_KEY_SIZE = 7;

/**** Public Fields ****/

// alarm_type_t alarm_type;

bool *debug_instrumentation;

/**** Private Prototypes****/

#ifdef UNIX
static bool
is_dr_takeover(app_pc tag);

extern void
_init();
#endif

#ifdef CROWD_SAFE_TRACK_MEMORY
static void
free_memory_allocation(void *allocation);

static int
find_allocation_overlap(void *span, void *allocation);

static int
compare_allocations(void *first, app_pc second);

static void
alloc_lock_acquire();

static void
alloc_lock_release();
#endif

static void
load_black_box_list();

static void
locate_monitor_dataset(OUT char *path, const char *monitor_dataset_dir);

static char*
load_environment_dir(OUT char *dir, const char *name, const char *default_value);

static void
init_application_short_name();

static void
call_stack_delete(call_stack_t *call_stack);

/**** Public Functions ****/

void
init_crowd_safe_log(bool is_fork, bool is_wow64_process) {
#ifdef CROWD_SAFE_LOG_ACTIVE
    char filename[256];
#endif

    dr_get_time(&process_start_time);

    if (is_fork) {
#ifdef CROWD_SAFE_LOG_ACTIVE
        dr_close_file(cs_log_file);
#endif
    } else {
        load_environment_dir((char*)&hashlog_dir, CROWD_SAFE_HASHLOG_DIR, DEFAULT_HASHLOG_DIRECTORY);

        parent_process_id = (int)dr_get_process_id();
    }

    init_application_short_name();

#ifdef CROWD_SAFE_LOG_ACTIVE
    generate_filename(filename, "process", "log");
    cs_log_file = create_output_file(filename);
#endif

    if (is_wow64_process) {
        stack_spy_sysnum_offset = 1;
        if (CROWD_SAFE_NETWORK_MONITOR())
            stack_spy_sysnums = stack_spy_sysnum_sets.wow64_netmon;
        else
            stack_spy_sysnums = stack_spy_sysnum_sets.wow64;
    } else {
        stack_spy_sysnum_offset = 0;
        if (CROWD_SAFE_NETWORK_MONITOR())
            stack_spy_sysnums = stack_spy_sysnum_sets.x86_netmon;
        else
            stack_spy_sysnums = stack_spy_sysnum_sets.x86;
    }
}

file_t create_early_dr_log() {
    char filename[256];
    generate_filename(filename, "early", "log");
    return dr_open_file(filename, DR_FILE_WRITE_REQUIRE_NEW);
}

void
init_crowd_safe_util(bool is_fork) {
    char cwd[256];
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    debug_instrumentation = CS_ALLOC(sizeof(bool));
    *debug_instrumentation = false;

    if (strcmp(application_short_name, "chrome.exe") == 0 && dr_get_current_directory(cwd, 256)) {
        is_chrome_child = (false && strstr(cwd, "Google") != NULL &&
                           strstr(cwd, "Application") != NULL &&
                           strstr(cwd, "Program Files") != NULL);
    }
    // verify_shadow_stack = is_chrome_child;
    verify_shadow_stack = false;
    CS_LOG("Starting %s instance %s shadow stack verification\n", application_short_name,
           verify_shadow_stack ? "with" : "without");

    /*
        if (parent_process_marker_file[strlen(parent_process_marker_file)-1] != '\\')
            strcat(parent_process_marker_file, "\\");
        strcat(parent_process_marker_file, application_short_name);
        strcat(parent_process_marker_file, ".parent");

        CS_LOG("Looking for parent marker file %s\n", parent_process_marker_file);

        is_child_by_marker = dr_file_exists(parent_process_marker_file);
        if (!is_child_by_marker) {
            file_t marker = dr_open_file(parent_process_marker_file, DR_FILE_WRITE_REQUIRE_NEW);
            if (marker == NULL)
                CS_ERR("Failed to create the parent process marker file\n");
            else
                dr_close_file(marker);
        }
    } else {
        CS_ERR("Failed to get the current directory\n");
        is_child_by_marker = false;
    }
    */

#ifdef CROWD_SAFE_TRACK_MEMORY
    if (!is_fork) {
        alloc_mutex = dr_mutex_create();
        memory_tracker_enabled = false;
        memory_tracker = (memory_tracker_t *)memory_tracker_alloc(sizeof(memory_tracker_t));
        memory_allocation_vector_init(&memory_tracker->allocations, 1000, false, free_memory_allocation, compare_allocations);
        memory_tracker->is_dirty = false;
        memory_tracker_enabled = true;
    }
#endif

#ifdef UNIX
    dr_takeover_complete = false;
    in_dr_takeover = false;
#endif
    if (!is_fork) {
        //metadata = CS_ALLOC(sizeof(crowd_safe_util_metadata_t));

        log_mutex = dr_mutex_create();
        CS_TRACK(log_mutex, sizeof(mutex_t));

        hashcode_mutex = dr_mutex_create();
        CS_TRACK(hashcode_mutex, sizeof(mutex_t));

        call_stack_mutex = dr_mutex_create();
        CS_TRACK(call_stack_mutex, sizeof(mutex_t));

        if (CROWD_SAFE_MONITOR()) {
            monitor_dataset_path = (char *)CS_ALLOC(256);
            locate_monitor_dataset(monitor_dataset_path, monitor_dataset_dir);
        } else {
            CS_DET("Monitor is not active.\n");
        }

        load_black_box_list();

        shadow_stack_missing_frame_lock = dr_mutex_create();
        shadow_stack_missing_frame_table = CS_ALLOC(sizeof(hashtable_t));
        hashtable_init_ex(
            shadow_stack_missing_frame_table,
            SHADOW_STACK_MISSING_FRAME_KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            NULL,
            NULL, /* no custom hashing */
            NULL);

        call_stack_table = CS_ALLOC(sizeof(call_stack_table_t));
        call_stack_table_init_ex(
            call_stack_table,
            CALL_STACK_TABLE_KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            call_stack_delete,
            NULL, /* no custom hashing */
            NULL);

        temp_tags = CS_ALLOC(sizeof(tag_vector_t));
        tag_vector_init(temp_tags, 0x20, false, NULL);

#ifdef UNIX
        plt_stubs = (hashtable_t*)CS_ALLOC(sizeof(hashtable_t));
        hashtable_init_ex(
            plt_stubs,
            TRAMPOLINE_TABLE_KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            NULL,
            NULL, /* no custom hashing */
            NULL);

        trampoline_trackers = (hashtable_t*)CS_ALLOC(sizeof(hashtable_t));
        hashtable_init_ex(
            trampoline_trackers,
            TRAMPOLINE_TABLE_KEY_SIZE,
            HASH_INTPTR,
            false,
            false,
            free_trampoline_tracker,
            NULL, /* no custom hashing */
            NULL);

        pending_trampolines = (drvector_t*)CS_ALLOC(sizeof(drvector_t));
        drvector_init(pending_trampolines, 10UL, false, NULL);


       CS_LOG("Trampoline hashtable entries at "PX" and "PX"\n", plt_stubs->table, trampoline_trackers->table);
#endif
    }

    {
        uint i;
        for (i = 0; i < TRACKED_SYSNUM_COUNT; i++) {
            syscall_trackers[i] = CS_ALLOC(sizeof(syscall_frequency_t));
            syscall_trackers[i]->count = 0U;
            init_report_mask(&syscall_trackers[i]->mask, 0xfff, 0xffffffff);
        }
    }
}

void
throw_app_exception(dcontext_t *dcontext) {
    fcache_enter_func_t fcache_enter = get_fcache_enter_shared_routine(dcontext);
    app_pc exception = get_do_throw_exception_entry(dcontext);
    extern mutex_t bb_building_lock;

    if (OWN_MUTEX(&bb_building_lock))
        mutex_unlock(&bb_building_lock);
    if (is_couldbelinking(dcontext))
        enter_nolinking(dcontext, NULL, true);

    CS_LOG("Throw app exception at pc "PX"\n", exception);

    enter_fcache(dcontext, fcache_enter, exception);
    ASSERT_NOT_REACHED();
}

#ifdef UNIX
bool
omit_bb_from_static_hash_output(app_pc tag) {
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, false);

    if (dr_takeover_complete)
        return false;

    if (in_dr_takeover) {
        if (!is_dr_takeover(tag)) {
            // the DR _init blocks will continue in succession without linking to any other
            // blocks until invoking the assembly routine "dynamorio_app_take_over", which
            // apparently has been dropped in the code cache apart from the bb generation
            // mechanism. The first block linkage we see after _init occurs between two
            // blocks of the target application, so we can safely turn off the filter.
            in_dr_takeover = false;
            dr_takeover_complete = true;
        }
    } else {
        if (is_dr_takeover(tag)) {
            in_dr_takeover = true;
        }
    }
    return in_dr_takeover;
}

void
pend_trampoline_caller(trampoline_tracker *trampoline, app_pc function_caller, int exit_ordinal,
        bool is_direct_link) {
    uint i;
    bool tracker_pending = false;
    trampoline_caller *caller;

    // pend the trampoline if it is not pending yet
    for (i = 0; i < pending_trampolines->entries; i++) {
        if (((trampoline_tracker*)drvector_get_entry(pending_trampolines, i)) == trampoline)
            tracker_pending = true;
    }
    if (!tracker_pending)
        drvector_append(pending_trampolines, trampoline);

    // pend the trampoline caller if not pending yet
    for (i = 0; i < trampoline->function_callers->entries; i++) {
        if (((trampoline_caller*)drvector_get_entry(trampoline->function_callers, i))->call_site == function_caller)
            return; // already pending
    }
    caller = (trampoline_caller*)CS_ALLOC(sizeof(trampoline_caller));
    caller->call_site = function_caller;
    caller->call_exit_ordinal = exit_ordinal;
    caller->is_direct_link = is_direct_link;
    drvector_append(trampoline->function_callers, caller);
}
#endif

#ifdef CROWD_SAFE_LOG_MEMORY
void *
log_memory_alloc(size_t size, const char *file, const char *function, int line) {
    void *mem = dr_global_alloc(size);
    log_memory((size_t)mem, size, file, function, line);
    return mem;
}

void
log_memory(size_t address, size_t size, const char *file, const char *function, int line) {
    CS_LOG("Mem | %lu at %s.%s(%d)\n", size, file, function, line);
}
#endif

#ifdef CROWD_SAFE_TRACK_MEMORY
void *
tracked_memory_alloc(size_t size, const char *file, const char *function, int line) {
    void *mem = dr_global_alloc(size);
    track_memory_alloc(mem, size, file, function, line);
    return mem;
}

void
track_memory_alloc(void *address, size_t size, const char *file, const char *function, int line) {
    memory_allocation_t *alloc;

    if (!memory_tracker_enabled)
        return;

    ASSERT(memory_tracker != NULL);
    alloc_lock_acquire();

    alloc = memory_tracker_alloc(sizeof(memory_allocation_t));
    alloc->address = address;
    alloc->size = size;
    alloc->file = file;
    alloc->function = function;
    alloc->line = line;
    memory_allocation_vector_insert(&memory_tracker->allocations, alloc, alloc->address);
    memory_tracker->is_dirty = true;

    alloc_lock_release();
}

void
untrack_memory_alloc(dcontext_t *dcontext, void *address) {
    alloc_lock_acquire();
    memory_allocation_vector_remove(&memory_tracker->allocations, address);
    alloc_lock_release();
}

void
report_memory_leak(app_pc start, app_pc end) {
    //memory_span_t span;
    //memory_allocation_t *allocation;

    CS_LOG("Memory leak: "PX" - "PX" (%d)\n", start, end, (end - start));

    /*
    if (!closed) {
        CS_STACKTRACE();
        alloc_lock_acquire();
    }

    span.start = start;
    span.end = end;

    allocation = memory_allocation_vector_overlap_search(&memory_tracker->allocations, span.start, span.end);
    if (allocation == NULL)
        CS_LOG("\tculprit not found.\n");
    else
        CS_LOG("\tculprit appears to be at %s:%s (%d)\n",
            allocation->file, allocation->function, allocation->line);

    if (!closed)
        alloc_lock_release();
    */
}
#endif

void
report_syscall_frequency(int sysnum) {
    // CS_LOG("Syscall: 0x%x\n", sysnum); // cs-hack: winsock

    if (sysnum < TRACKED_SYSNUM_COUNT) {
        syscall_frequency_t *tracker = syscall_trackers[sysnum];
        tracker->count++;
        if (is_report_threshold(&tracker->mask, tracker->count))
            CS_LOG("Frequent syscall: 0x%x x %d\n", sysnum, tracker->count);
    }
}

uint
current_thread_id() {
#ifdef UNIX
    return pthread_self();
#elif defined WINDOWS
    return GetCurrentThreadId();
#endif
}

ushort
observe_call_stack(dcontext_t *dcontext)
{
    priv_mcontext_t *mc = get_mcontext(dcontext);
    ptr_uint_t *next_pc, *pc = (ptr_uint_t *) (app_pc)mc->xbp;
    uint frame_count = 0;
    app_pc return_address;
    uint64 hash = 0ULL;
    call_stack_t *matching_stack;

    CALL_STACK_LOCK;
    while (pc != NULL && is_readable_without_exception_query_os((byte *)pc, 8)) {
        frame_count++;
        next_pc = (ptr_uint_t *) *pc;
        if (pc != next_pc) {
            return_address = (app_pc) *(pc + 1);
            if (return_address == 0)
                break;

            tag_vector_append(temp_tags, return_address);
            hash = hash ^ (hash << 5) ^ (uint) pc;
        }
        if (frame_count > 100)
            break;
        pc = next_pc;
    }

    matching_stack = (call_stack_t *) call_stack_table_lookup(call_stack_table, hash);
    if (matching_stack == NULL) {
        ushort id = write_call_stack(temp_tags->array, temp_tags->entries);
        CS_DET("Created new call stack for hash 0x%llx\n", hash);

        matching_stack = CS_ALLOC(sizeof(call_stack_t));
        matching_stack->id = id;
        matching_stack->hash = hash;
        matching_stack->tags = *temp_tags; // fieldwise copy
        tag_vector_init(temp_tags, 0x20, false, NULL); // regenerate temp_tags
        call_stack_table_add(call_stack_table, hash, matching_stack);
    } else {
        CS_DET("Found call stack for hash 0x%llx\n", hash);
        tag_vector_clear(temp_tags);
    }
    CALL_STACK_UNLOCK;

    return matching_stack->id;
}

void
dump_stack_trace(file_t file) {
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    print_stacktrace(file);
}

const char *
edge_type_string(graph_edge_type type) {
    switch (type) {
        case indirect_edge: return "indirect";
        case direct_edge: return "direct";
        case call_continuation_edge: return "call-continuation";
        case exception_continuation_edge: return "exception-continuation";
        case unexpected_return_edge: return "unexpected-return";
        case gencode_perm_edge: return "gencode-perm";
        case gencode_write_edge: return "gencode-write";
        default: return "<unknown>";
    }
}

#ifdef UNIX
void
free_trampoline_tracker(void *trampoline) {
    ASSERT(((trampoline_tracker*)trampoline)->function_callers == NULL);
    dr_global_free(trampoline, sizeof(trampoline_tracker));
}

void
free_trampoline_caller(void *caller) {
    dr_global_free(caller, sizeof(trampoline_caller));
}
#endif

void
generate_filename(char *buffer, const char *basename, const char *suffix) {
    ssize_t index = 0, dir_length;

    dir_length = strlen(hashlog_dir);
    strncpy(buffer + index, hashlog_dir, dir_length);
    index += dir_length;

    strncpy(buffer + index, application_short_name, application_short_name_length);
    index += application_short_name_length;

    strncpy(buffer + index, ".", 1);
    index++;
    strncpy(buffer + index, basename, strlen(basename));
    index += strlen(basename);

    dr_snprintf(buffer + index, 64 + strlen(suffix), ".%4d-%02d-%02d.%02d-%02d-%02d.%d-%d.%s",
        process_start_time.year, process_start_time.month, process_start_time.day,
        process_start_time.hour, process_start_time.minute, process_start_time.second,
        parent_process_id, dr_get_process_id(), suffix);
}

file_t
create_output_file(const char *filename) {
    file_t result;
    CROWD_SAFE_DEBUG_HOOK(__FUNCTION__, (file_t)0x0);

    result = dr_open_file(filename, DR_FILE_WRITE_REQUIRE_NEW);
    if (result == INVALID_FILE) {
        if (dr_file_exists(filename))
            dr_fprintf(STDERR, "Error: unable to create file %s because it already exists!\n");
        else
            dr_fprintf(STDERR, "Error: unable to create file %s!\n");
    }

    CS_LOG("Created Crowd-Safe output file %s\n", filename);
    return result;
}

static void
print_shadow_stack_internal(const char *tag, int frame_number, shadow_stack_frame_t *top) {
    int i;

    CS_LOCKED_LOG("%sshadow-stack T%x %d("PX")", tag, current_thread_id(), frame_number, top->return_address);
    for (i = 1; i <= frame_number; i++) {
        CS_LOCKED_LOG(" %d("PX")", frame_number-i, (top-i)->return_address);
        //if (i % 4 == 0)
        //    CS_LOG("\n             ");
    }
    CS_LOCKED_LOG("\n");
}

void
print_shadow_stack(dcontext_t *dcontext) {
    local_crowd_safe_data_t *csd = GET_CS_DATA(dcontext);
    int frame_number = SHADOW_STACK_FRAME_NUMBER(csd, SHADOW_FRAME(csd));
    shadow_stack_frame_t *top = SHADOW_FRAME(csd);

    print_shadow_stack_internal("#xlate#", frame_number, top);
}

#define FRAME_RETURN_ADDRESS(bp) ((app_pc) *((bp)+1))

static bool
scan_for_address(app_pc *start, app_pc *end, app_pc address) {
    app_pc *walk;

    for (walk = start; walk < end; walk++) {
        if (*walk == address)
            return true;
    }
    return false;
}

static bool
scan_for_matching_shadow_stack_frame(app_pc addr, shadow_stack_frame_t **frame,
                                     int *error_frame, bool is_top, uint scan_limit) {
    uint i, j;
    shadow_stack_frame_t *next = *frame;

    for (i = 0; i < scan_limit; i++, next--) {
        if (next->return_address == addr) {
            app_pc shadow_return_address;

            for (j = (is_top ? 1 : 0); j < i; j++) {
                shadow_return_address = (*frame-j)->return_address;
                if (hashtable_lookup(shadow_stack_missing_frame_table, shadow_return_address) == NULL) {
                    CS_WARN("T%x Extraneous shadow stack frame %d("PX")\n",
                            current_thread_id(), *error_frame - j, shadow_return_address);
                    hashtable_add(shadow_stack_missing_frame_table, shadow_return_address, SHADOW_STACK_MISSING_FRAME);
                }
            }

            *frame = next;
            *error_frame -= i;
            return true;
        }
    }
    return false;
}

bool
return_address_iterator_start(return_address_iterator_t *i, ptr_uint_t *start) {
    if (start == NULL)
        return false;

    i->bp_current = start;
    if (!is_readable_without_exception_query_os((byte *)start, 8) || FRAME_RETURN_ADDRESS(start) < int2p(0x40000))
        return false;

    i->bp_next = (ptr_uint_t *) *start;
    if ((p2int(i->bp_next) - p2int(start)) > 0x1000)
        return false;

    i->bp_walk = NULL;
    i->is_complete = false;
    return true;
}

bool
return_address_iterator_next(return_address_iterator_t *i, app_pc *out_addr, app_pc target) {
    ptr_uint_t *bp_next;
    bool has_next = false;

    if (i->is_complete)
        return false;

    while (true) {
        if (i->bp_walk == NULL) {
            *out_addr = FRAME_RETURN_ADDRESS(i->bp_current);
            i->bp_walk = i->bp_current + 2;
            i->is_in_ebp_chain = true;
            has_next = true;
            break;
        } else {
            app_pc next_addr;

            if (is_readable_without_exception_query_os((byte *)i->bp_next, 8) && /* favor the ebp chain */
                FRAME_RETURN_ADDRESS(i->bp_next) == target) {
                i->bp_current = i->bp_next;
                bp_next = (ptr_uint_t *) *i->bp_next;
                if (bp_next == i->bp_next) { /* todo: scrub duplicate code snippets */
                    i->is_complete = true;
                    break;
                }
                i->bp_next = bp_next;
                i->bp_walk = NULL;
                if ((i->bp_next - i->bp_current) > 0x1000) { /* end if foobar */
                    i->is_complete = true;
                    break;
                }
                continue;
            }

            while (i->bp_walk < i->bp_next) {
                next_addr = int2p(*i->bp_walk);
                i->bp_walk++;
                if (next_addr > int2p(0x40000) && is_executable_address_locked(next_addr)) {
                    *out_addr = next_addr;
                    i->is_in_ebp_chain = false;
                    has_next = true;
                    break;
                }
            }
            if (has_next)
                break;
        }
        if (i->bp_walk >= i->bp_next) {
            if (!is_readable_without_exception_query_os((byte *)i->bp_next, 8) || FRAME_RETURN_ADDRESS(i->bp_next) == NULL) {
                i->is_complete = true;
                break;
            } else {
                i->bp_current = i->bp_next;
                bp_next = (ptr_uint_t *) *i->bp_next;
                if (bp_next == i->bp_next) {
                    i->is_complete = true;
                    break;
                }
                i->bp_next = bp_next;
                i->bp_walk = NULL;

                if ((i->bp_next - i->bp_current) > 0x1000) { /* end if foobar */
                    i->is_complete = true;
                    break;
                }
            }
        }
    }
    return has_next;
}

void
log_shadow_stack(dcontext_t *dcontext, local_crowd_safe_data_t *csd, const char *tag) {
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    int frame_number = SHADOW_STACK_FRAME_NUMBER(csd, SHADOW_FRAME(csd)), error_frame = frame_number;
    shadow_stack_frame_t *top = SHADOW_FRAME(csd), *frame = top;
    bool has_entry = false, is_correct = true;
    priv_mcontext_t *mc = get_mcontext(dcontext);
    ptr_uint_t *bp = (ptr_uint_t *) (app_pc)mc->xbp;

    if (frame_number > 1 && verify_shadow_stack) {
        ptr_uint_t *next_bp;
        app_pc app_return_address;

        if (!return_address_iterator_start(cstl->stack_walk, bp)) {
            CS_DET("Can't verify shadow stack at bp="PX"\n", mc->xbp);
            return;
        }

        dr_mutex_lock(shadow_stack_missing_frame_lock);
        executable_areas_read_lock();
        while (return_address_iterator_next(cstl->stack_walk, &app_return_address, frame->return_address)) {
            if (error_frame < 0) {
                CS_ERR("Shadow stack underflow!\n");
                is_correct = false;
                break;
            }
            if (scan_for_matching_shadow_stack_frame(app_return_address, &frame, &error_frame,
                                                     frame == top, MAX(3, error_frame))) {
                frame--;
                error_frame--;
                if (frame->return_address == int2p(SHADOW_STACK_CALLBACK_TAG))
                    break;
            } else if (frame != top) { /* top frame may be missing */
                if (hashtable_lookup(shadow_stack_missing_frame_table, app_return_address) == NULL) {
                    hashtable_add(shadow_stack_missing_frame_table, app_return_address, SHADOW_STACK_MISSING_FRAME);
                    if (cstl->stack_walk->is_in_ebp_chain) {
                        is_correct = false;
                        CS_ERR("T%x Shadow stack is missing a frame with return address "PX"\n",
                               current_thread_id(), app_return_address);
                        break;
                    } else {
                        CS_WARN("T%x Shadow stack may be missing a frame with return address "PX"\n",
                                current_thread_id(), app_return_address);
                    }
                }
            }
        }

#ifdef DEBUG
        if (!is_correct) { /* repeat for debugging */
            frame = top;
            error_frame = frame_number;
            return_address_iterator_start(cstl->stack_walk, bp);
            while (return_address_iterator_next(cstl->stack_walk, &app_return_address, frame->return_address)) {
                if (error_frame < 0) {
                    break;
                }
                if (scan_for_matching_shadow_stack_frame(app_return_address, &frame, &error_frame,
                                                         frame == top, MAX(3, error_frame))) {
                    frame--;
                    error_frame--;
                } else {
                    if (cstl->stack_walk->is_in_ebp_chain) {
                        break;
                    }
                }
            }
        }
#endif

        executable_areas_read_unlock();
        dr_mutex_unlock(shadow_stack_missing_frame_lock);

        if (is_correct) {
            /*
            module_location_t *top_module = get_module_for_address(top->return_address);
            if (top_module != NULL && strcmp(top_module->module_name, "dwrite.dll") == 0) {
                log_lock_acquire();
                CS_LOCKED_LOG("App stack: ");
                bp = (ptr_uint_t *) (app_pc)mc->xbp;
                while (bp != NULL && is_readable_without_exception_query_os((byte *)bp, 8)) {
                    next_bp = (ptr_uint_t *) *bp;
                    CS_LOCKED_LOG("%x ", *(bp+1));
                    bp = next_bp;
                }
                CS_LOCKED_LOG("\n");
                CS_LOCKED_LOG("Matched %d of %d shadow stack frames. All frames appear to be correct.\n",
                              frame_number - error_frame, frame_number);
                print_shadow_stack_internal("-correct-", frame_number, top);
                log_lock_release();
            }
            */
        } else {
            uint count = 0;

            log_lock_acquire();
            CS_LOCKED_LOG("Error at shadow frame %d: ", error_frame);
            bp = (ptr_uint_t *) (app_pc)mc->xbp;
            while (bp != NULL && is_readable_without_exception_query_os((byte *)bp, 8)) {
                if (*(bp+1) < 0x40000)
                    break;
                next_bp = (ptr_uint_t *) *bp;
                CS_LOCKED_LOG("%x ", *(bp+1));
                bp = next_bp;
                if (++count > 200)
                    break;
            }
            CS_LOCKED_LOG("\n");
            print_shadow_stack_internal("-error-", frame_number, top);
            log_lock_release();
        }

        if (has_entry) {
            CS_DET(" @"PX" | last fragment "PX" | next tag "PX"\n", p2int(XSP(dcontext)),
                   dcontext->last_fragment == NULL ? 0 : dcontext->last_fragment->tag, dcontext->next_tag);
        }
    }

    if (frame_number < 0) {
        CS_ERR("%sshadow-frame %d!\n", tag, frame_number);
        has_entry = true;
    }
}

void
close_crowd_safe_util() {
    uint i;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    dr_global_free(debug_instrumentation, sizeof(bool));

    dr_mutex_destroy(shadow_stack_missing_frame_lock);
    hashtable_delete(shadow_stack_missing_frame_table);
    dr_global_free(shadow_stack_missing_frame_table, sizeof(hashtable_t));

#ifdef UNIX
    hashtable_delete(plt_stubs);
    hashtable_delete(trampoline_trackers);
    drvector_delete(pending_trampolines);
    dr_global_free(plt_stubs, sizeof(hashtable_t));
    dr_global_free(trampoline_trackers, sizeof(hashtable_t));
    dr_global_free(pending_trampolines, sizeof(drvector_t));
#endif

    if (CROWD_SAFE_MONITOR()) {
        dr_global_free(monitor_dataset_path, 256);
    }

    for (i = 0; i < TRACKED_SYSNUM_COUNT; i++)
        dr_global_free(syscall_trackers[i], sizeof(syscall_frequency_t));

    for (i = 0; i < black_boxes->entries; i++)
        dr_global_free(black_boxes->array[i], sizeof(anonymous_black_box_t));
    drvector_delete(black_boxes);
    dr_global_free(black_boxes, sizeof(drvector_t));

    dr_mutex_destroy(hashcode_mutex);
#ifdef CROWD_SAFE_TRACK_MEMORY
    dr_mutex_destroy(alloc_mutex);
#endif
    closed = true;
}

void
close_crowd_safe_log() {
#ifdef CROWD_SAFE_TRACK_MEMORY
    // too late?
    //memory_allocation_vector_delete(&memory_tracker->allocations);
    //dr_global_free(memory_tracker, sizeof(memory_tracker_t));
#endif

#ifdef CROWD_SAFE_LOG_ACTIVE
    CS_LOG("\t>> Closed crowd_safe_util.\n");
    dr_close_file(cs_log_file);
#endif

    dr_mutex_destroy(log_mutex);
}

/**** Private Functions ****/

#ifdef UNIX
static inline bool
is_dr_takeover(app_pc tag) {
    return (((ptr_uint_t)tag >= (ptr_uint_t)_init) && ((ptr_uint_t)tag < (ptr_uint_t)(p2int((void*)_init) + 0x80ULL)));
}
#endif

#ifdef CROWD_SAFE_TRACK_MEMORY
static void
free_memory_allocation(void *allocation) {
    dr_global_free(allocation, sizeof(memory_allocation_t));
}

static int
find_allocation_overlap(void *span, void *allocation) {
    memory_allocation_t *memory_allocation = (memory_allocation_t *)allocation;
    memory_span_t *memory_span = (memory_span_t *)span;

    if (memory_span->start >= (memory_allocation->address + memory_allocation->size))
        return 1;
    if (memory_span->end < memory_allocation->address)
        return -1;
    return 0;
}

static int
compare_allocations(void *first, app_pc second) {
    return (int)(((memory_allocation_t *)first)->address - second);
}
#endif

static void
load_black_box_list() {
    char *black_box_config_path, *line, *mark, edge_id[256];
    file_t black_box_config;
    uint64 size;
    ssize_t read_count;
    void *buffer;

    black_box_config_path = getenv(ENV_DYNAMORIO_HOME);
    if (black_box_config_path[strlen(black_box_config_path) - 1] != FILE_SEPARATOR_CHAR)
        strcat(black_box_config_path, FILE_SEPARATOR_STRING);
    strcat(black_box_config_path, BLACK_BOX_CONFIG_FILENAME);
    black_box_config = dr_open_file(black_box_config_path, DR_FILE_READ);
    if (black_box_config == INVALID_FILE) {
        CS_ERR("Failed to load the anonymous black box configuration file at %s. Invalid file handle received.\n",
            black_box_config_path);
        return;
    }

    dr_file_size(black_box_config, &size);
    if (size == 0ULL) {
        CS_ERR("Failed to load the anonymous black box configuration file at %s. Size is zero.\n", black_box_config_path);
        return;
    }

    buffer = CS_ALLOC((size_t)size);
    read_count = dr_read_file(black_box_config, buffer, (size_t)size);
    if (read_count < size) {
        CS_ERR("Failed to load the anonymous black box configuration file at %s. Read only %d of %d bytes\n",
            black_box_config_path, read_count, size);
    } else {
        black_boxes = (drvector_t *)CS_ALLOC(sizeof(drvector_t));
        drvector_init(black_boxes, 4U, false, NULL);

        for (line = strtok_r(buffer, "\r\n", &mark); line; line = strtok_r(NULL, "\r\n", &mark)) {
            anonymous_black_box_t *black_box = (anonymous_black_box_t *)CS_ALLOC(sizeof(anonymous_black_box_t));
            black_box->module_name = line;
            print_blackbox_entry(edge_id, 256, line);
            black_box->entry_hash = string_hash(edge_id);
            print_blackbox_exit(edge_id, 256, line);
            black_box->exit_hash = string_hash(edge_id);
            drvector_append(black_boxes, black_box);

            CS_DET("Black box owner %s has entry hash 0x%llx and exit hash 0x%llx\n",
                   line, black_box->entry_hash, black_box->exit_hash);
        }

        dr_close_file(black_box_config);
    }
    dr_global_free(buffer, (size_t)size);
}

static void
locate_monitor_dataset(OUT char *path, const char *monitor_dataset_dir) {
    char *line, *mark, *monitor_filename, map_file_path[256] = {0};
    file_t map_file;
    uint64 size;
    ssize_t read_count;
    void *buffer;

    strcat(map_file_path, monitor_dataset_dir);
    strcat(map_file_path, PROCESS_DATASET_MAP_FILENAME);
    map_file = dr_open_file(map_file_path, DR_FILE_READ);
    if (map_file == INVALID_FILE) {
        CS_ERR("Failed to load the process dataset map file at %s. Invalid file handle received.\n",
            map_file_path);
        return;
    }

    dr_file_size(map_file, &size);
    if (size == 0ULL) {
        CS_ERR("Failed to load the process dataset map file at %s. Size is zero.\n", map_file_path);
        return;
    }

    buffer = CS_ALLOC((size_t)size);
    read_count = dr_read_file(map_file, buffer, (size_t)size);
    if (read_count < size) {
        CS_ERR("Failed to load the process dataset map file at %s. Read only %d of %d bytes\n",
            map_file_path, read_count, size);
    } else {
        path[0] = '\0';
        for (line = strtok_r(buffer, "\r\n", &mark); line; line = strtok_r(NULL, "\r\n", &mark)) {
            if (strmincmp(application_short_name, line) == 0) {
                monitor_filename = strstr(line, "|") + 1;

                strcat(path, monitor_dataset_dir);
                strcat(path, monitor_filename);
                break;
            }
        }

        dr_close_file(map_file);
    }
    dr_global_free(buffer, (size_t)size);
}

static char*
load_environment_dir(OUT char *dir, const char *name, const char *default_value) {
    char *dir_env;

    dir_env = getenv(name);
    if ((dir_env == NULL) || (strlen(dir_env) == 0))
        strcpy(dir, default_value);
    else
        strcpy(dir, dir_env);

    if (dir[strlen(dir) - 1] != FILE_SEPARATOR_CHAR)
        strcat(dir, FILE_SEPARATOR_STRING);

    return dir;
}

static void
init_application_short_name() {
    char *slash, *application_name = get_application_name();

    while (true) {
        slash = strstr(application_name, FILE_SEPARATOR_STRING);
        if (slash == NULL)
            break;
        application_name = slash+1;
    }
    application_short_name_length = strlen(application_name);
    strncpy(application_short_name, application_name, application_short_name_length);
    application_short_name[application_short_name_length] = '\0';
    strcasecpy((char*)&application_short_name, application_name, true);
}

#ifdef CROWD_SAFE_TRACK_MEMORY
static void
alloc_lock_acquire() {
    if (!self_owns_dynamo_vm_area_lock())
        dr_mutex_lock(alloc_mutex);
}

static void
alloc_lock_release() {
    if (!self_owns_dynamo_vm_area_lock())
        dr_mutex_unlock(alloc_mutex);
}

static void*
memory_tracker_alloc(size_t size) {
    //return dr_nonheap_alloc(size, DR_MEMPROT_READ | DR_MEMPROT_WRITE);
    return dr_global_alloc(size);
}
#endif

static void
call_stack_delete(call_stack_t *call_stack)
{
    tag_vector_delete(&call_stack->tags);
    dr_global_free(call_stack, sizeof(call_stack_t));
}
