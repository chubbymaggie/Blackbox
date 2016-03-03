#ifndef CROWD_SAFE_UTIL_H
#define CROWD_SAFE_UTIL_H 1

//#include "../../core/globals.h"
//#include "../../core/fragment.h"
//#include "../../core/vmareas.h"
//#include "../../core/x86/instrument.h"
#include "../common/utils.h"

#ifdef ASSERT
# undef ASSERT
#endif
#define ASSERT(condition) DR_ASSERT_MSG(condition, ##condition)
#define ASSERT_NOT_REACHED() ASSERT(false)

#include "drhashtable.h"
#include "drvector.h"
#include "indirect_link_observer.h"

#ifdef UNIX
# include <sys/syscall.h>
# include <string.h>
# include <ctype.h>
#endif

#define PRAGMA_VALUE_TO_STRING(x) #x
#define PRAGMA_VALUE(x) PRAGMA_VALUE_TO_STRING(x)
#define PRAGMA_VAR_NAME_VALUE(var) #var "=" PRAGMA_VALUE(var)
// use it like this: #pragma message(PRAGMA_VAR_NAME_VALUE(SOMETHING))

#define DODEBUG(statement) do { statement } while (0)

#define CS_LOG_NONE 0
#define CS_LOG_ERRORS 1
#define CS_LOG_WARNINGS 2
#define CS_LOG_MESSAGES 3
#define CS_LOG_DETAILS 4
#define CS_LOG_ALL_CALLS 5

#define CROWD_SAFE_LOG_LEVEL CS_LOG_MESSAGES
//#define CROWD_SAFE_LOG_MEMORY 1
//#define CROWD_SAFE_DYNAMIC_IMPORTS: not in here, see arch_exports.h
#define LOG_ANONYMOUS_ASSEMBLY 1
//#define ANALYZE_UNEXPECTED_SUBGRAPHS 1
#define MONITOR_UNEXPECTED_IBP 1
//#define MONITOR_ENTRY_RATE 1
//#define MONITOR_UIBP_ONLINE 1 // requires MONITOR_UNEXPECTED_IBP
//#define MONITOR_ALL_IBP 1 // requires MONITOR_UNEXPECTED_IBP. It always monitors every ibp.
//#define GENCODE_CHUNK_STUDY 1
//#define REPORT_SYSCALL_FREQUENCY 1
//#define SYSTEM_TIME_RDTSC 1

#ifdef REPORT_SYSCALL_FREQUENCY
//# define REPORT_ALL_SYSCALLS 1
#endif

#ifdef DEBUG
//# define CROWD_SAFE_TRACK_MEMORY 1
#endif

// #define WAIT_FOR_DEBUGGER_ON_ERROR 1

#ifdef CROWD_SAFE_DATA
# define CROWD_SAFE_ENABLED true
#else
# define CROWD_SAFE_ENABLED false
#endif

#ifdef CROWD_SAFE_INTEGRATION
# define _CROWD_SAFE(fragment) , fragment
# define _CROWD_SAFE_DECLARE(field) field
#else
# define _CROWD_SAFE(fragment)
# define _CROWD_SAFE_DECLARE(field)
#endif

#ifdef UNIX
# define p2int(value) ((uint64)(value))
# define int2p(value) (value)
#else
# define p2int(value) ((uint)(value))
# define int2p(value) ((app_pc)(value))
#endif

#ifdef SYSTEM_TIME_RDTSC
# pragma intrinsic(__rdtsc)
typedef uint64 clock_type_t;
# define BUFFER_FLUSH_INTERVAL 0x10000000ULL
# define UIBP_REPORT_INTERVAL 0x4000000000ULL
#else // SYSTEM_TIME_KUSER
typedef uint clock_type_t;
# define BUFFER_FLUSH_INTERVAL 0x1000U
# define UIBP_REPORT_INTERVAL 0x10000U
#endif

//#define SEED_TLS_FOR_IBL_VERIFICATION 1
#ifdef SEED_TLS_FOR_IBL_VERIFICATION
# define VALUE_OR_SEED(value) PC(0x12345678)
#else
# define VALUE_OR_SEED(value) value
#endif

#ifdef UNIX
# define IS_CONTEXT_SWITCH(sysnum) (sysnum == SYS_rt_sigreturn)
#else
# define IS_CONTEXT_SWITCH(sysnum) ((sysnum == 0x2) || (sysnum == 0x40))
#endif

#define OPND_TLS_FIELD(offset) dr_create_audit_tls_slot(offset)

#define IMM_TO_TLS(dc, val, offs) \
    INSTR_CREATE_mov_imm(dc, OPND_TLS_FIELD(offs), OPND_CREATE_INT32(val))

/* Generates an instr_t for a `mov` instruction from `reg` to TLS at `offset`.
 * Parameter `reg` must be of type `reg_id_t`, as defined in instr.h, and
 * parameter `offset` will typically be defined in arch_exports.h. */
#define SAVE_TO_TLS(dc, reg, offs) dr_create_save_to_audit_tls(dc, reg, offs)

/* Generates an instr_t for a `mov` instruction from TLS at `offset` to `reg`.
 * Parameter types are the same as SAVE_TO_TLS */
#define RESTORE_FROM_TLS(dc, reg, offs) dr_create_restore_from_audit_tls(dc, reg, offs)

#ifdef X64
# define MASK_LOW(val) (uint32)(p2int(val) & 0xFFFFFFFFUL)
# define MASK_HIGH(val) (uint32)(p2int(val) >> 0x20)
#else
# define MASK_LOW(val) val
// MASK_HIGH is not valid in x32
#endif

#define CROWD_SAFE_MONITOR_OPTION 1
#define CROWD_SAFE_ALARM_OPTION 2
#define CROWD_SAFE_NETWORK_MONITOR_OPTION 4
#define CROWD_SAFE_META_ON_CLOCK_OPTION 8
#define CROWD_SAFE_RECORD_XHASH_OPTION 0x10
#define CROWD_SAFE_DEBUG_SCRIPT_OPTION 0x20
#define CROWD_SAFE_BB_ANALYSIS_OPTION 0x40
#define CROWD_SAFE_MONITOR() is_crowd_safe_option_active(CROWD_SAFE_MONITOR_OPTION)
#define CROWD_SAFE_ALARM() is_crowd_safe_option_active(CROWD_SAFE_ALARM_OPTION)
#define CROWD_SAFE_NETWORK_MONITOR() is_crowd_safe_option_active(CROWD_SAFE_NETWORK_MONITOR_OPTION)
#define CROWD_SAFE_META_ON_CLOCK() is_crowd_safe_option_active(CROWD_SAFE_META_ON_CLOCK_OPTION)
#define CROWD_SAFE_RECORD_XHASH() is_crowd_safe_option_active(CROWD_SAFE_RECORD_XHASH_OPTION)
#define CROWD_SAFE_DEBUG_SCRIPT() is_crowd_safe_option_active(CROWD_SAFE_DEBUG_SCRIPT_OPTION)
#define CROWD_SAFE_BB_ANALYSIS() is_crowd_safe_option_active(CROWD_SAFE_BB_ANALYSIS_OPTION)

// CS-TODO: verify correctness of big/little endianness
#ifndef __BYTE_ORDER
# if defined(__sparc) || defined(__sparc__) \
   || defined(_POWER) || defined(__powerpc__) \
   || defined(__ppc__) || defined(__hpux) || defined(__hppa) \
   || defined(_MIPSEB) || defined(_POWER) \
   || defined(__s390__)
#  define __BYTE_ORDER __BIG_ENDIAN
# elif defined(__i386__) || defined(__alpha__) \
   || defined(__ia64) || defined(__ia64__) \
   || defined(_M_IX86) || defined(_M_IA64) \
   || defined(_M_ALPHA) || defined(__amd64) \
   || defined(__amd64__) || defined(_M_AMD64) \
   || defined(__x86_64) || defined(__x86_64__) \
   || defined(_M_X64) || defined(__bfin__)
#  define __BYTE_ORDER __LITTLE_ENDIAN
# endif
#endif

#ifdef __BYTE_ORDER
    #if __BYTE_ORDER == __BIG_ENDIAN
        #define STATIC_SYSCALL(opcode, sysnum) \
            (((uint)(sysnum) >> 24) | ((uint)(opcode) >> 16))
    #elif __BYTE_ORDER == LITTLE_ENDIAN
        #define STATIC_SYSCALL(opcode, sysnum) \
            (((uint)(sysnum) << 24 >> 24) | ((uint)(opcode) << 24 >> 16))
    #else
        #error "Endian specifier '__BYTE_ORDER' has an unrecognized value!"
    #endif
#else
    #error "Endian specifier '__BYTE_ORDER' not defined!"
#endif

#ifdef UNIX
# define min(a, b) (a) < (b) ? (a) : (b)
# define max(a, b) (a) > (b) ? (a) : (b)
#endif

#define WDB_NONE 0U
#define WDB_ANY ~0U
#define WDB_UR_SYMBOLS 1U
#define WDB_MODE WDB_UR_SYMBOLS
#define CROWD_SAFE_WDB_SCRIPT(mode) (((mode & WDB_MODE) > 0) && CROWD_SAFE_DEBUG_SCRIPT())

#ifdef X64
# define ALL_LOWER_BITS 0xFFFFFFFFFULL
# define PC(constant) constant##ULL
# define PX "0x%llx"
#else
# define PC(constant) constant##UL
# define PX "0x%lx"
#endif

#define UINT_FIELD(p, offset) (*(((uint *) p) + offset))
#define USHORT_FIELD(p, offset) (*(((ushort *) p) + offset))

#define IBP_META_NEW_PATH 0x10UL
#define IBP_META_STACK_PENDING 0x8UL
#define IBP_META_PATH_PENDING 0x4UL
#define IBP_META_RETURN 0x2UL // N.B.: value is inverted for efficient processing in assembly
#define IBP_META_UNEXPECTED_RETURN 0x1UL

#define IBP_META_MASK(ibp_data, flags) (p2int(ibp_data->ibp_from_tag) & flags)
#define IBP_SET_META(ibp_data, op, bits) ibp_data->flags = ibp_data->flags op bits

#define IBP_IS_NEW_PATH(ibp_data) ((ibp_data->flags & IBP_META_NEW_PATH) > 0UL)
#define IBP_STACK_IS_PENDING(ibp_data) ((ibp_data->flags & IBP_META_STACK_PENDING) > 0UL)
#define IBP_PATH_IS_PENDING(ibp_data) ((ibp_data->flags & IBP_META_PATH_PENDING) > 0UL)
#define IBP_IS_RETURN(ibp_data) (((ibp_data)->flags & IBP_META_RETURN) == 0UL)
#define IBP_IS_UNEXPECTED_RETURN(ibp_data) \
    ((ibp_data->flags & (IBP_META_RETURN | IBP_META_UNEXPECTED_RETURN)) == \
        IBP_META_UNEXPECTED_RETURN)
#define IBP_IS_PENDING_TAG(ibp_data, tag) \
    ((uint)ibp_data->ibp_from_tag > 1U) && (ibp_data->ibp_to_tag == tag)

#define GET_CS_DATA(dcontext) (dcontext_get_audit_state(dcontext))
#define GET_IBP_METADATA(dcontext) (&dcontext_get_audit_state(dcontext)->ibp_data)

#define ANONYMOUS_MODULE_NAME "|anonymous|"
#define UNKNOWN_MODULE_NAME "|unknown|"
#define DYNAMORIO_MODULE_NAME "|dynamorio|"
#define SYSCALL_MODULE_NAME "|system|"

#define PROCESS_ENTRY_POINT int2p(3)
#define PROCESS_ENTRY_HASH ((bb_hash_t)3ULL)

#define SYSTEM_ENTRY_POINT int2p(1) // for thread start and callbacks
#define SYSTEM_ENTRY_HASH ((bb_hash_t)1ULL)

#define SYSCALL_SINGLETON_HASH ((bb_hash_t)2ULL)
#define SYSCALL_SINGLETON_START int2p(0x1000)
#define SYSCALL_SINGLETON_END int2p(0x5000)

#define CHILD_PROCESS_SINGLETON_PC int2p(4)
#define CHILD_PROCESS_SINGLETON_HASH ((bb_hash_t)3ULL)

#define BLACK_BOX_SINGLETON_FAKE_PC_OFFSET 0x100

#define MODULAR_PC(module, absolute_pc) \
    ((module->type == module_type_image) ? ((app_pc)(absolute_pc - module->start_pc)) : absolute_pc)

#define GET_LAST_DECODED_TAG(cstl) (cstl->bb_meta.last_decoded_tag)
#define GET_BUILDING_TAG(cstl) (cstl->bb_meta.building_tag)
#define GET_BB_STATE(cstl) (cstl->bb_meta.state)
#define GET_STATIC_SYSCALL_NUMBER(cstl) (cstl->bb_meta.syscall_number)
#define GET_STATIC_SYSCALL_ORDINAL(cstl) (cstl->bb_meta.syscall_ordinal)
#define GET_CLOBBERED_BLACK_BOX_HASH(cstl) (cstl->bb_meta.clobbered_black_box_hash)
#define IS_BUILDING_TAG(cstl, tag) (cstl->bb_meta.building_tag == tag)
#define IS_BLACK_BOX_THRASH(cstl) (cstl->bb_meta.is_black_box_thrash)
#define IS_EXCEPTION_RESUMING(cstl) (cstl->bb_meta.is_exception_resuming)
#define HAS_STATIC_SYSCALL(cstl) (cstl->bb_meta.syscall_number >= 0)
#define HAS_CLOBBERED_BLACK_BOX_HASH(cstl) (cstl->bb_meta.clobbered_black_box_hash != 0ULL)
#define SET_STATIC_SYSCALL_NUMBER(cstl, sysnum) (cstl->bb_meta.syscall_number = sysnum)
#define SET_STATIC_SYSCALL_ORDINAL(cstl, ordinal) (cstl->bb_meta.syscall_ordinal = ordinal)
#define SET_CLOBBERED_BLACK_BOX_HASH(cstl, hash) (cstl->bb_meta.clobbered_black_box_hash = hash)
#define SET_BLACK_BOX_THRASH(cstl) (cstl->bb_meta.is_black_box_thrash = true)
#define SET_EXCEPTION_RESUMING(cstl) (cstl->bb_meta.is_exception_resuming = true)

#define GET_CSTL(dcontext) \
    ((crowd_safe_thread_local_t *) (dcontext_get_audit_state(dcontext)->security_audit_thread_local))
#define SET_CSTL(dcontext, cstl) \
do { \
    local_security_audit_state_t *csd = dcontext_get_audit_state(dcontext); \
    csd->security_audit_thread_local = cstl; \
    cstl->csd = csd; \
} while (0)

#define GET_SHADOW_STACK_BASE(sas) \
    (((crowd_safe_thread_local_t *)((sas)->security_audit_thread_local))->shadow_stack_base)
#define SHADOW_STACK_FRAME_NUMBER(sas, frame) (frame - GET_SHADOW_STACK_BASE(sas))

#if (CROWD_SAFE_LOG_LEVEL > CS_LOG_NONE)
# define CROWD_SAFE_LOG_ACTIVE 1
#endif

// cs-todo: the lock doesn't work well because it gets trapped under other locks,
//          e.g. when arguments are lock-acquiring function calls. Need to resolve
//          everything to primitives before grabbing the log lock--dr_snprintf?

    //log_lock_acquire();
    //log_lock_release();
#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_ERRORS)
# define CS_ERR(...) \
do { \
    dr_fprintf(cs_log_file, "Error: "__VA_ARGS__); \
} while(0)
# define CS_NOLOCK_ERR(...) dr_fprintf(cs_log_file, "Error: "__VA_ARGS__)
# define IF_ERR(x) x
#else
# define CS_ERR(...)
# define CS_NOLOCK_ERR(...)
# define IF_ERR(x)
#endif

    //log_lock_acquire();
    //log_lock_release();
#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_WARNINGS)
# define CS_WARN(...) \
do { \
    dr_fprintf(cs_log_file, "Warning: "__VA_ARGS__); \
} while(0)
# define IF_WARN(x) x
#else
# define CS_WARN(...)
# define IF_WARN(x)
#endif

    //log_lock_acquire();
    //log_lock_release();
#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_MESSAGES)
# define CS_LOG(...) \
do { \
    dr_fprintf(cs_log_file, __VA_ARGS__); \
} while(0)
    //assert_log_lock();
# define CS_LOCKED_LOG(...) \
do { \
    dr_fprintf(cs_log_file, __VA_ARGS__); \
} while(0)
# define CS_NOLOCK_LOG(...) dr_fprintf(cs_log_file, __VA_ARGS__)
# define CS_STACKTRACE() dump_dr_callstack(cs_log_file)
# define IF_LOG(x) x
#else
# define CS_LOG(...)
# define CS_LOCKED_LOG(...)
# define CS_NOLOCK_LOG(...)
# define CS_STACKTRACE()
# define IF_LOG(x)
#endif

#if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_DETAILS)
# define CS_DET(...) dr_fprintf(cs_log_file, __VA_ARGS__)
# define IF_DET(x) x
#else
# define CS_DET(...)
# define IF_DET(x)
#endif

#define CROWD_SAFE_DATA 1
#ifdef CROWD_SAFE_DATA
#  define CROWD_SAFE_DEBUG_HOOK_QUIET(function, value)
#  define CROWD_SAFE_DEBUG_HOOK_QUIET_VOID(function)
# if (CROWD_SAFE_LOG_LEVEL >= CS_LOG_ALL_CALLS)
#   define CROWD_SAFE_DEBUG_HOOK(function, value) dr_fprintf(cs_log_file, "\t[CS: %s]\n", function)
#   define CROWD_SAFE_DEBUG_HOOK_VOID(function) dr_fprintf(cs_log_file, "\t[CS: %s]\n", function)
# else
#   define CROWD_SAFE_DEBUG_HOOK(function, value)
#   define CROWD_SAFE_DEBUG_HOOK_VOID(function)
# endif
#else
#  define CROWD_SAFE_DEBUG_HOOK_QUIET(function, value) return value
#  define CROWD_SAFE_DEBUG_HOOK_QUIET_VOID(function) return
# if (CROWD_SAFE_LOG_LEVEL > 1)
#   define CROWD_SAFE_DEBUG_HOOK(function, value) dr_fprintf(cs_log_file, "\t[CS: %s]\n", function); return value
#   define CROWD_SAFE_DEBUG_HOOK_VOID(function) dr_fprintf(cs_log_file, "\t[CS: %s]\n", function); return
# else
#   define CROWD_SAFE_DEBUG_HOOK(function, value) return value
#   define CROWD_SAFE_DEBUG_HOOK_VOID(function) return
# endif
#endif

#define MAX_APP_STACK_FRAMES 0x20

#ifdef CROWD_SAFE_TRACK_MEMORY
# define CS_ALLOC(size) tracked_memory_alloc(size, __FILE__, __FUNCTION__, __LINE__)
# define CS_TRACK(location, size) track_memory_alloc(location, size, __FILE__, __FUNCTION__, __LINE__)
#else
# ifdef CROWD_SAFE_LOG_MEMORY
#  define CS_ALLOC(size) log_memory_alloc(size, __FILE__, __FUNCTION__, __LINE__)
#  define CS_TRACK(location, size) log_memory(location, size, __FILE__, __FUNCTION__, __LINE__)
# else
#  define CS_ALLOC(size) dr_global_alloc(size)
#  define CS_TRACK(location, size)
# endif
#endif

#define BB_STATE_LIVE 1
#define BB_STATE_COMMITTED 2
#define BB_STATE_LINKED 4
#define BB_STATE_SINGLETON 8
#define BB_STATE_BLACK_BOX 0x10
#define BB_STATE_EXCEPTION 0x20
#define BB_STATE_DYNAMO 0x40
#define BB_STATE_DYNAMO_INTERCEPT 0x80
#define BB_STATE_MONITORED 0x100
#define BB_STATE_MONITOR_MISS 0x200
#define BB_STATE_UNEXPECTED_RETURN 0x400

#define IS_BLACK_BOX(module) (module->black_box_singleton != 0ULL)
#define IS_BB_LIVE(state) ((state)->flags & BB_STATE_LIVE)
#define ACTIVATE_BB(state) ((state)->flags |= BB_STATE_LIVE)
#define DEACTIVATE_BB(state) ((state)->flags &= ~BB_STATE_LIVE)
#define IS_BB_COMMITTED(state) ((state)->flags & BB_STATE_COMMITTED)
#define SET_BB_COMMITTED(state) ((state)->flags |= BB_STATE_COMMITTED)
#define RESET_BB_COMMITTED(state) ((state)->flags &= ~BB_STATE_COMMITTED)
#define IS_BB_LINKED(state) ((state)->flags & BB_STATE_LINKED)
#define SET_BB_LINKED(state) ((state)->flags |= BB_STATE_LINKED)
#define RESET_BB_LINKED(state) ((state)->flags &= ~BB_STATE_LINKED)
#define IS_BB_SINGLETON(state) ((state)->flags & BB_STATE_SINGLETON)
#define IS_BB_BLACK_BOX(state) ((state)->flags & BB_STATE_BLACK_BOX)
#define SET_BB_BLACK_BOX(state) ((state)->flags |= BB_STATE_BLACK_BOX)
#define UNSET_BB_BLACK_BOX(state) ((state)->flags &= ~BB_STATE_BLACK_BOX)
#define IS_BB_WHITE_BOX(module, state) (((module)->type == module_type_anonymous) && !((state)->flags & BB_STATE_BLACK_BOX))
#define IS_BB_EXCEPTION(state) ((state)->flags & BB_STATE_EXCEPTION)
#define SET_BB_EXCEPTION(state) ((state)->flags |= BB_STATE_EXCEPTION)
#define UNSET_BB_EXCEPTION(state) ((state)->flags &= ~BB_STATE_EXCEPTION)
#define IS_BB_DYNAMO(state) ((state)->flags & BB_STATE_DYNAMO)
#define SET_BB_DYNAMO(state) ((state)->flags |= BB_STATE_DYNAMO)
#define IS_BB_DYNAMO_INTERCEPT(state) ((state)->flags & BB_STATE_DYNAMO_INTERCEPT)
#define SET_BB_DYNAMO_INTERCEPT(state) ((state)->flags |= BB_STATE_DYNAMO_INTERCEPT)
#define IS_BB_MONITORED(state) ((state)->flags & BB_STATE_MONITORED)
#define SET_BB_MONITORED(state) ((state)->flags |= BB_STATE_MONITORED)
#define IS_BB_MONITOR_MISS(state) (((state)->flags & BB_STATE_MONITOR_MISS) > 0)
#define SET_BB_MONITOR_MISS(state) ((state)->flags |= BB_STATE_MONITOR_MISS)
#define IS_BB_UNEXPECTED_RETURN(state) (((state)->flags & BB_STATE_UNEXPECTED_RETURN) > 0)
#define SET_BB_UNEXPECTED_RETURN(state) ((state)->flags |= BB_STATE_UNEXPECTED_RETURN)
#define UNSET_BB_UNEXPECTED_RETURN(state) ((state)->flags &= ~BB_STATE_UNEXPECTED_RETURN)

#define IS_GENCODE_EDGE(edge_type) ((edge_type == gencode_perm_edge) || (edge_type == gencode_write_edge))

#define FCACHE_TRANSITION_LATENCY 50
#define UIBP_INTERVAL_COUNT 4

/* Specific type for BB hashcodes, which are comprised strictly of instruction
 * content and any dynamic syscall numbers. */
typedef uint64 bb_hash_t;

typedef enum graph_edge_type graph_edge_type;
enum graph_edge_type {
    indirect_edge = 0,
    direct_edge = 1,
    call_continuation_edge = 2,
    exception_continuation_edge = 3,
    unexpected_return_edge = 4,
    gencode_perm_edge = 5,
    gencode_write_edge = 6,
    fork_edge = 7
};

typedef enum graph_meta_type graph_meta_type;
enum graph_meta_type {
    graph_non_meta,
    graph_meta_singleton,
    graph_meta_trampoline,
    graph_meta_return,
    graph_meta_signal_handler,
    graph_meta_sigreturn,
};

/* Specifies the content levels of the BB analysis file. */
enum {
    BB_ANALYSIS_NONE,
    BB_ANALYSIS_ASSEMBLY,
    BB_ANALYSIS_BLOCK_INFO,
    BB_ANALYSIS_HASH_INFO,
    BB_ANALYSIS_PAIR_HASHES
};

#pragma pack(push, 2)
typedef struct _bb_state_t {
    ushort image_instance_id;
    ushort flags;
    bb_hash_t hash;
    graph_meta_type meta_type;
    byte tag_version;
    ushort size;
} bb_state_t;
#pragma pack(pop)

#ifdef UNIX
typedef struct trampoline_tracker trampoline_tracker;
struct trampoline_tracker {
    app_pc *plt_cell;
    drvector_t *function_callers;
    app_pc trampoline_entry;
    app_pc function_entry;
};

typedef struct trampoline_caller trampoline_caller;
struct trampoline_caller {
    app_pc call_site;
    int call_exit_ordinal;
    bool is_direct_link;
};
#endif

typedef struct monitor_module_data_t monitor_module_data_t;
typedef struct module_relocations_t module_relocations_t;

/* Template instantiation: relocation_target_table_t */
#define HASHTABLE_NAME_KEY relocation_target_table
#define HASHTABLE_KEY_TYPE ptr_uint_t
#define HASHTABLE_PAYLOAD_TYPE ptr_uint_t
#include "../drcontainers/drhashtable.h"

typedef enum module_type module_type;
enum module_type {
    module_type_image = 0,
    module_type_anonymous = 1,
    module_type_meta = 2,
    module_type_dynamo = 3,
};

typedef struct report_mask_t report_mask_t;
struct report_mask_t {
    uint mask;
    uint max_mask;
};

#ifdef MONITOR_UIBP_ONLINE
typedef struct module_unexpected_ibt_t module_unexpected_ibt_t;
struct module_unexpected_ibt_t {
    report_mask_t target_report_mask;
    uint admitted_targets;
    uint suspicious_targets;
    report_mask_t invocation_report_mask;
    uint admitted_target_invocations;
    uint suspicious_target_invocations;
    clock_type_t first_admitted_target_invocation;
    clock_type_t last_admitted_target_invocation;
    clock_type_t first_suspicious_target_invocation;
    clock_type_t last_suspicious_target_invocation;
};
#endif

typedef struct module_location_t module_location_t;
struct module_location_t {
    app_pc start_pc;
    app_pc end_pc;
    module_relocations_t *relocation_table;
    relocation_target_table_t *relocation_targets;
    monitor_module_data_t *monitor_data;
    char *module_name;
    module_type type;
    ushort image_instance_id;
    app_pc black_box_singleton; // non-zero for anonymous blackboxes only
    bb_state_t *black_box_singleton_state; // non-null for anonymous blackboxes only
    bb_hash_t black_box_entry; // for anonymous, non-zero for black boxes only
    bb_hash_t black_box_exit;  // for anonymous, non-zero for black boxes only
    drvector_t *gencode_from_tags;
    uint intra_module_singleton_edge_misses;
#ifdef MONITOR_UIBP_ONLINE
    module_unexpected_ibt_t unexpected_ibt;
#endif
#ifdef WINDOWS
    uint64 version; /**< file version number from .rsrc section */
    uint checksum;  /**< module checksum from the PE headers */
    uint timestamp; /**< module timestamp from the PE headers */
#endif
} unknown_module, system_module;

typedef struct _stack_frame_t {
    union {
        app_pc return_address;
        app_pc writer_tag;
    };
    module_location_t *module;
} stack_frame_t;

typedef struct basic_block_meta_t basic_block_meta_t;
struct basic_block_meta_t { // maintained for disappearing anonymous 'from' nodes in direct edges
    app_pc building_tag;
    app_pc last_decoded_tag;
    bb_state_t *state;
    int syscall_number;
    byte syscall_ordinal;
    bb_hash_t clobbered_black_box_hash;
    bool is_black_box_thrash;
    bool is_exception_resuming;
#ifdef DEBUG
    bool created_ibp_edge;
#endif
};

#ifdef MONITOR_UIBP_ONLINE
typedef struct thread_unexpected_ibp_t thread_unexpected_ibp_t;
struct thread_unexpected_ibp_t {
    uint total;
    uint within_expected;
    uint within_unexpected;
    uint from_expected;
    uint to_expected;
    report_mask_t report_mask;
};
#endif

typedef struct thread_clock_t thread_clock_t;
struct thread_clock_t {
    clock_type_t last_fcache_entry;
    clock_type_t clock;
    bool is_in_app_fcache;
    clock_type_t last_uibp_timestamp;
    clock_type_t last_suibp_timestamp;
    clock_type_t last_uibp_is_admitted;
    uint consecutive_interval_count[UIBP_INTERVAL_COUNT];
    uint consecutive_admitted_interval_count[UIBP_INTERVAL_COUNT];
    uint consecutive_suspicious_interval_count[UIBP_INTERVAL_COUNT];
};

typedef struct stack_suspicion_t stack_suspicion_t;
struct stack_suspicion_t {
    ushort uib_count;
    ushort suib_count;
    bool raising_edge_is_cross_module;
    uint raising_edge_index;
};

typedef struct _return_address_iterator_t {
    ptr_uint_t *bp_current;
    ptr_uint_t *bp_next;
    ptr_uint_t *bp_walk;
    bool is_in_ebp_chain;
    bool is_complete;
} return_address_iterator_t;

typedef struct crowd_safe_thread_local_t crowd_safe_thread_local_t;
struct crowd_safe_thread_local_t {
    local_security_audit_state_t *csd;
    shadow_stack_frame_t *shadow_stack_base;
    basic_block_meta_t bb_meta;
#ifdef MONITOR_ENTRY_RATE
    clock_type_t thread_init_tsc;
    uint dr_entry_count;
#endif
#ifdef MONITOR_UIBP_ONLINE
    thread_unexpected_ibp_t thread_uibp;
#endif
#ifdef MONITOR_UNEXPECTED_IBP
    thread_clock_t thread_clock;
    stack_suspicion_t stack_suspicion;
#endif
    return_address_iterator_t *stack_walk;
};

typedef struct anonymous_black_box_t anonymous_black_box_t;
struct anonymous_black_box_t {
    char *module_name;
    bb_hash_t entry_hash;
    bb_hash_t exit_hash;
};

typedef enum alarm_type_t alarm_type_t;
enum alarm_type_t {
    ALARM_OFF,
    ALARM_LOG,
    ALARM_EXCEPTION,
    ALARM_NOTIFY_AND_EXIT
};

drvector_t *resolved_imports;
drvector_t *black_boxes;

/* Singleton instance of the process log file */
file_t cs_log_file;

#ifdef UNIX
hashtable_t *plt_stubs;
app_pc plt_stub_token;

hashtable_t *trampoline_trackers;
drvector_t *pending_trampolines;
#endif

void
init_crowd_safe_log(bool is_fork, bool is_wow64_process);

file_t
create_early_dr_log();

/* Initialize util structures, including the BB analysis file (if requested),
 * and the DR takeover state flags which are used to filter the DR takeover
 * BBs from the hash sets. */
void
init_crowd_safe_util(bool isFork);

void
throw_app_exception(dcontext_t *dcontext);

#ifdef UNIX
/* Filter for BB blocks, which currently just omits the DR takeover BBs. */
bool
omit_bb_from_static_hash_output(app_pc tag);

void
pend_trampoline_caller(trampoline_tracker *trampoline, app_pc function_caller,
    int exit_ordinal, bool is_direct_link);
#endif

#ifdef CROWD_SAFE_LOG_MEMORY
void *
log_memory_alloc(size_t size, const char *file, const char *function, int line);

void
log_memory(size_t address, size_t size, const char *file, const char *function, int line);
#endif

#ifdef CROWD_SAFE_TRACK_MEMORY
void *
tracked_memory_alloc(size_t size, const char *file, const char *function, int line);

void
track_memory_alloc(void *address, size_t size, const char *file, const char *function, int line);

void
untrack_memory_alloc(dcontext_t *dcontext, void *address);

void
report_memory_leak(app_pc start, app_pc end);
#endif

void
report_syscall_frequency(int sysnum);

uint
current_thread_id();

uint
get_app_stacktrace(dcontext_t *dcontext, uint max_frames, stack_frame_t *frames);

ushort
observe_call_stack(dcontext_t *dcontext);

void
dump_stack_trace();

const char *
edge_type_string(graph_edge_type type);

#ifdef LINUX
/* Free a trampoline tracker. */
void
free_trampoline_tracker(void *trampoline);

void
free_trampoline_caller(void *caller);
#endif

/* Generate a filename in the standard CrowdSafe log format:
 *
 *     <basename>.MM-dd-yy.HH-mm-ss.dat */
void
generate_filename(char *buffer, const char *basename, const char *suffix);

file_t
create_output_file(const char *filename);

void
print_shadow_stack(dcontext_t *dcontext);

void
log_shadow_stack(dcontext_t *dcontext, local_security_audit_state_t *csd, const char *tag);

/* Close the BB analysis file, if it was in use. */
void
close_crowd_safe_util();

void
close_crowd_safe_log();

/******** inline definitions **********/

inline void
log_lock_acquire() {
    extern void *log_mutex;
    if (log_mutex != NULL)
        dr_mutex_lock(log_mutex);
}

inline void
log_lock_release() {
    extern void *log_mutex;
    if (log_mutex != NULL)
        dr_mutex_unlock(log_mutex);
}

inline void
assert_log_lock() {
    extern void *log_mutex;
    if (log_mutex != NULL)
        ASSERT(dr_mutex_self_owns(log_mutex));
}

inline void
hashcode_lock_acquire() {
    extern void *hashcode_mutex;
    extern void *output_mutex;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    dr_mutex_lock(hashcode_mutex);
    ASSERT(!dr_mutex_self_owns(output_mutex));
}

inline void
hashcode_lock_release() {
    extern void *hashcode_mutex;
    CROWD_SAFE_DEBUG_HOOK_VOID(__FUNCTION__);

    dr_mutex_unlock(hashcode_mutex);
}

inline void
assert_hashcode_lock() {
    extern void *hashcode_mutex;

    ASSERT(dr_mutex_self_owns(hashcode_mutex));
}

inline void
assert_no_hashcode_lock() {
    extern void *hashcode_mutex;
    ASSERT(!dr_mutex_self_owns(hashcode_mutex));
}

inline void
clear_pending_ibp(ibp_metadata_t *ibp_data) {
    IBP_SET_META(ibp_data, &, ~IBP_META_PATH_PENDING);
    IBP_SET_META(ibp_data, &, IBP_META_RETURN); // value inverted for efficient processing in assembly
    ibp_data->ibp_from_tag = PC(0);
}

inline void
check_shadow_stack_bounds(local_security_audit_state_t *csd)
{
    shadow_stack_frame_t *base = GET_SHADOW_STACK_BASE(csd);
    if (csd->shadow_stack <= base || csd->shadow_stack > base + SHADOW_STACK_SIZE) {
        CS_ERR("<ss> Shadow stack pointer "PX" out of bounds ["PX","PX"] on thread 0x%x\n",
            csd->shadow_stack, base, base + SHADOW_STACK_SIZE, current_thread_id());
        ASSERT(false);
    }
}

inline void
log_bb_state(bb_state_t *state, const char *name) {
    if (state == NULL) {
        CS_LOG("State '%s' is null\n", name);
    } else {
        CS_LOG("State '%s' belongs to image %d. Flags 0x%x. Hash 0x%llx. Type %d. Version %d\n",
            name, state->image_instance_id, state->flags, state->hash, state->meta_type, state->tag_version);
    }
}

inline void
log_bb_meta(basic_block_meta_t *bb_meta) {
    CS_LOG("Building block "PX". Last decoded block "PX"\n", bb_meta->building_tag,
        bb_meta->last_decoded_tag);
    CS_LOG("\t");
    log_bb_state(bb_meta->state, "cstl->bb_meta.state");
    CS_LOG("\tSysnum %d at ordinal %d. Clobbered hash 0x%llx %s thrashing.\n",
        bb_meta->syscall_number, bb_meta->syscall_ordinal, bb_meta->clobbered_black_box_hash,
        (bb_meta->is_black_box_thrash ? "and" : "and not"));
}

inline void
validate_ordinal(dcontext_t *dcontext, app_pc from, app_pc to, byte exit_ordinal, graph_edge_type edge_type) {
    if (exit_ordinal < 2)
        return;
    if ((edge_type == call_continuation_edge) && (exit_ordinal < 3))
        return;
    if (((edge_type == exception_continuation_edge) || (edge_type == gencode_perm_edge)) && (exit_ordinal < 4))
        return;
    if ((edge_type == gencode_write_edge) && (exit_ordinal < 5))
        return;

    CS_WARN("High ordinal %d for edge type %d: "PX" to "PX"\n", exit_ordinal,
            edge_type, from, to);
    dr_fragment_log_ordinals(dcontext, from, "\t", 3);
}

inline byte default_edge_ordinal(graph_edge_type edge_type) {
    switch (edge_type) {
        case gencode_perm_edge:
            return 3;
        case gencode_write_edge:
            return 4;
        case fork_edge:
            return 5;
        default:
            return 0; /* for branch taken */
    }
}

inline void
start_decoding(crowd_safe_thread_local_t *cstl, app_pc tag) {
    cstl->bb_meta.building_tag = tag;
}

inline void
set_building_complete(crowd_safe_thread_local_t *cstl) {
    cstl->bb_meta.last_decoded_tag = cstl->bb_meta.building_tag;
    cstl->bb_meta.building_tag = NULL;
    cstl->bb_meta.state = NULL;
    cstl->bb_meta.clobbered_black_box_hash = 0ULL;
    cstl->bb_meta.is_black_box_thrash = false;
    cstl->bb_meta.is_exception_resuming = false;
    cstl->bb_meta.syscall_number = -1;
}

inline void
assign_to_black_box(bb_state_t *state) {
    SET_BB_BLACK_BOX(state);
    SET_BB_COMMITTED(state);
    SET_BB_LINKED(state);
}

/* Sometimes DR will decode a block with a different length, even though the code has not changed.
   The phony new version will mess up the graph, so just roll the state back to the previous
   version and do not write anything. */
inline void
reconcile_decode_anomaly(crowd_safe_thread_local_t *cstl, bb_state_t *state) {
    state->tag_version--;
    RESET_BB_COMMITTED(state); // might write a duplicate, but better than having none
    SET_BB_LINKED(state);

    if (cstl->bb_meta.clobbered_black_box_hash == 0ULL) {
        CS_LOG("Restore tag version %d at "PX"\n", state->tag_version, GET_BUILDING_TAG(cstl));
    } else {
        CS_DET("Restore black box version %d at "PX"\n", state->tag_version, GET_BUILDING_TAG(cstl));

        assign_to_black_box(state);
    }
}

inline bool
is_crowd_safe_option_active(uint option) {
    extern uint crowd_safe_options;
    return (crowd_safe_options & option) > 0;
}

inline bb_hash_t
string_hash(const char *string) {
    int c;
    bb_hash_t hash = 0ULL;

    while (true) {
        c = *string++;
        if (!c)
            break;
        hash = hash ^ (hash << 5) ^ c;
    }
    return hash;
}

inline bb_hash_t
wstring_hash(const wchar_t *string) {
    wchar_t c;
    bb_hash_t hash = 0ULL;

    while (true) {
        c = *string++;
        if (!c)
            break;
        hash = hash ^ (hash << 5) ^ c;
    }
    return hash;
}

inline void
print_callback_function_id(char *buffer, size_t length, module_location_t *module, size_t offset) {
    dr_snprintf(buffer, length, "%s!@%x", module->module_name, offset);
}

inline void
print_module_id(char *buffer, size_t length, module_location_t *module) {
    dr_snprintf(buffer, length, "%s-%llx-%x-%x", module->module_name,
                module->version, module->timestamp, module->checksum);
}

inline void
print_blackbox_entry(char *buffer, size_t length, const char *from_module_name) {
    dr_snprintf(buffer, length, "%s/<anonymous>!callback", from_module_name);
}

inline void
print_blackbox_exit(char *buffer, size_t length, const char *to_module_name) {
    dr_snprintf(buffer, length, "<anonymous>/%s!callback", to_module_name);
}

inline bool
is_report_threshold(report_mask_t *report_mask, uint count) {
    if ((report_mask->mask & count) == 0) {
        if (report_mask->mask < report_mask->max_mask)
            report_mask->mask = (report_mask->mask << 1) | 1;
        return true;
    }
    return false;
}

inline void
init_report_mask(report_mask_t *report_mask, uint start, uint max) {
    report_mask->mask = start;
    report_mask->max_mask = max;
}

#ifdef MONITOR_UNEXPECTED_IBP
# ifdef MONITOR_UIBP_ONLINE
inline void
report_unexpected_ibt(module_location_t *module) {
    module_unexpected_ibt_t uibt = module->unexpected_ibt;
    clock_type_t average_admitted_target_interval = 0ULL, average_suspicious_target_interval = 0ULL;

    if (uibt.admitted_target_invocations > 0)
        average_admitted_target_interval = (uibt.last_admitted_target_invocation - uibt.first_admitted_target_invocation) /
            (clock_type_t)uibt.admitted_target_invocations;
    if (uibt.suspicious_target_invocations > 0)
        average_suspicious_target_interval = (uibt.last_suspicious_target_invocation - uibt.first_suspicious_target_invocation) /
            (clock_type_t)uibt.suspicious_target_invocations;

    CS_LOG("UIBT| targets from %s (%d Adm, %d Susp) Invocations (%d Adm, %d Susp) Interval (%llu Adm, %llu Susp)\n",
        module->module_name, uibt.admitted_targets, uibt.suspicious_targets, uibt.admitted_target_invocations,
        uibt.suspicious_target_invocations, average_admitted_target_interval, average_suspicious_target_interval);
}

inline void
report_unexpected_ibt_at_interval(module_location_t *module) {
    if (is_report_threshold(&module->unexpected_ibt.target_report_mask,
            module->unexpected_ibt.admitted_targets + module->unexpected_ibt.suspicious_targets) ||
            is_report_threshold(&module->unexpected_ibt.invocation_report_mask,
            module->unexpected_ibt.admitted_target_invocations + module->unexpected_ibt.suspicious_target_invocations))
        report_unexpected_ibt(module);
}

inline void
init_unexpected_ibt(module_location_t *module) {
    init_report_mask(&module->unexpected_ibt.target_report_mask, 0xf, 0xfff);
    module->unexpected_ibt.admitted_targets = 0;
    module->unexpected_ibt.suspicious_targets = 0;
    init_report_mask(&module->unexpected_ibt.invocation_report_mask, 0xffff, 0xffffffff);
    module->unexpected_ibt.admitted_target_invocations = 0;
    module->unexpected_ibt.suspicious_target_invocations = 0;
    module->unexpected_ibt.first_admitted_target_invocation = 0ULL;
    module->unexpected_ibt.last_admitted_target_invocation = 0ULL;
    module->unexpected_ibt.first_suspicious_target_invocation = 0ULL;
    module->unexpected_ibt.last_suspicious_target_invocation = 0ULL;
}
# endif

inline clock_type_t
quick_system_time_millis() {
#ifdef SYSTEM_TIME_RDTSC
    return __rdtsc();
#else
    KUSER_SHARED_DATA *kud = (KUSER_SHARED_DATA *) KUSER_SHARED_DATA_ADDRESS;
    return (kud->SystemTime.High1Time << 0x10) | (kud->SystemTime.LowPart >> 0x10);
#endif
}

inline void
start_fcache_clock(dcontext_t *dcontext, bool is_direct_return) {
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    if (!is_direct_return) // else leave it as is
        cstl->thread_clock.is_in_app_fcache = true;
    cstl->thread_clock.last_fcache_entry = quick_system_time_millis();
}

inline void
stop_fcache_clock(dcontext_t *dcontext) {
    crowd_safe_thread_local_t *cstl = GET_CSTL(dcontext);
    if (cstl->thread_clock.is_in_app_fcache)
        cstl->thread_clock.clock +=
            (quick_system_time_millis() - cstl->thread_clock.last_fcache_entry - FCACHE_TRANSITION_LATENCY);
    cstl->thread_clock.is_in_app_fcache = false;
}
#endif

inline bool
is_stack_spy_sysnum(int sysnum) {
#ifdef REPORT_ALL_SYSCALLS
    return true;
#else
    extern const uint *stack_spy_sysnums;
    extern uint stack_spy_sysnum_offset;
    if (sysnum < 0x1000) {
        int sysnum_index = (sysnum-stack_spy_sysnum_offset);
        uint spy_sysnum_set = stack_spy_sysnums[(sysnum_index >> 5)];
        uint sysnum_mask = (1 << (sysnum_index & 0x1f));
        return (spy_sysnum_set & sysnum_mask) > 0;
    }
    return false;
#endif
}

inline uint64
get_system_time_millis() {
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    return ((((uint64) time.dwHighDateTime) << 0x20) | (uint64) time.dwLowDateTime);
}

inline int
strcasemincmp(const char *left, const char *right) {
    int i, cmp, length = min(strlen(left), strlen(right));
    for (i = 0; i < length; i++) {
        cmp = tolower(left[i]) - tolower(right[i]);
        if (cmp != 0)
            return cmp;
    }
    return 0;
}

inline int
strmincmp(const char *left, const char *right) {
    int i, cmp, length = min(strlen(left), strlen(right));
    for (i = 0; i < length; i++) {
        cmp = left[i] - right[i];
        if (cmp != 0)
            return cmp;
    }
    return 0;
}

inline void
strcasecpy(char *dst, const char *src, bool lowercase) {
    if (lowercase) {
        for(; *src; dst++, src++)
            *dst = (char)tolower(*src);
    } else {
        for(; *src; dst++, src++)
            *dst = (char)toupper(*src);
    }
    *(dst) = '\0';
}

inline char*
strtok_r(char *str, const char *delim, char **nextp) {
    char *ret;

    if (str == NULL)
        str = *nextp;

    str += strspn(str, delim);
    if (*str == '\0')
        return NULL;

    ret = str;
    str += strcspn(str, delim);

    if (*str)
        *str++ = '\0';

    *nextp = str;
    return ret;
}

inline char *
cs_strcpy(const char *src) {
    size_t write_len = strlen(src) + 1;
    char *dst = CS_ALLOC(write_len);
    strncpy(dst, src, write_len);
    return dst;
}

inline void
cs_strfree(char *str) {
    dr_global_free(str, strlen(str) + 1);
}
#endif
