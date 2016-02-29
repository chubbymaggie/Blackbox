#include "crowd_safe_util.h"
#include "crowd_safe_trace.h"
#include "network_monitor.h"

#define NET_WARN(...) CS_WARN("NET| "__VA_ARGS__)
#define NET_LOG(...) CS_LOG("NET| "__VA_ARGS__)
#define NET_DET(...) CS_DET("NET| "__VA_ARGS__)

typedef enum _nt_status_code {
    NT_STATUS_SUCCESS = 0,
    NT_STATUS_PENDING = 0x103,
    NT_STATUS_CONNECTION_REFUSED = 0xc0000236
} nt_status_code;

typedef enum _network_socket_state_t {
    SOCKET_UNBOUND,
    SOCKET_BOUND,
    SOCKET_CONNECTED,
    SOCKET_CLOSED
} network_socket_state_t;

typedef enum _pending_operation_t {
    PENDING_NONE,
    PENDING_BIND,
    PENDING_UDP_RECEIVE,
    PENDING_TCP_CONNECT,
    PENDING_TCP_SEND,
    PENDING_TCP_RECEIVE
} pending_operation_t;

typedef enum _tdi_flag_t {
    TDI_NORMAL = 0x20,
    TDI_PEEK = 0x80
} tdi_flag_t;

typedef struct _network_socket_t {
    ushort id;
    HANDLE handle;
    HANDLE event;
    network_socket_state_t state;
    pending_operation_t op;
    network_address_t src;
    network_address_t dst; // for UDP, this is the most recent observed link destination
    IO_STATUS_BLOCK *status;
    byte *pending_data;
} network_socket_t;

typedef struct _socket_buffer_t {
    uint size;
    byte *data;
} socket_buffer_t;

typedef struct _network_monitor_metadata_t {
    ushort next_socket_id;
} network_monitor_metadata_t;

static network_monitor_metadata_t *metadata;
static hashtable_t *socket_table;

static void *socket_lock;

#define SMALL_TABLE_KEY_SIZE 7

#define NET_LOCK dr_mutex_lock(socket_lock)
#define NET_UNLOCK dr_mutex_unlock(socket_lock)

#define IP "%d.%d.%d.%d"
#define SPLIT_IP(ip) (ip & 0xff), ((ip >> 8) & 0xff), ((ip >> 0x10) & 0xff), ((ip >> 0x18) & 0xff)
#define PORT(port) (((port & 0xff) << 8) | (port >> 8))
#define LINK "[%d.%d.%d.%d:%d->%d.%d.%d.%d:%d]"
#define SOCKET_LINK(s) SPLIT_IP(s->src.ip), PORT(s->src.port), SPLIT_IP(s->dst.ip), PORT(s->dst.port)

static network_address_t empty_address = { 0, 0 };

static void
network_socket_delete(void *socket);

static void
pending_operation_completed(dcontext_t *dcontext, network_socket_t *socket);

static bool
control_code_is_recognized(IoControlCode code);

static bool
control_code_is_reported(IoControlCode code);

void
init_network_monitor() 
{
    socket_table = CS_ALLOC(sizeof(hashtable_t));
    hashtable_init_ex(
        socket_table,
        SMALL_TABLE_KEY_SIZE,
        HASH_INTPTR,
        false,
        false,
        NULL, 
        NULL, /* no custom hashing */
        NULL);
    
    metadata = CS_ALLOC(sizeof(network_monitor_metadata_t));
    metadata->next_socket_id = 0;
    
    socket_lock = dr_mutex_create();
}

void
notify_socket_created(HANDLE socket_handle)
{
    network_socket_t *socket = CS_ALLOC(sizeof(network_socket_t));
    socket->id = metadata->next_socket_id++;
    socket->handle = socket_handle;
    socket->state = SOCKET_UNBOUND;
    socket->op = PENDING_NONE;
    socket->src.ip = 0;
    socket->src.port = 0;
    socket->dst.ip = 0;
    socket->dst.port = 0;
    
    NET_LOCK;
    hashtable_add(socket_table, socket_handle, socket);
    NET_UNLOCK;
    
    NET_DET("Socket 0x%x created.\n", socket_handle);
}

void
notify_device_io_control(dcontext_t *dcontext, uint result, HANDLE socket_handle, HANDLE event, 
    IO_STATUS_BLOCK *status_block, IoControlCode control_code, byte *input_data, uint input_length, 
    byte *output_data, uint output_length)
{
    ushort call_stack_id;
    network_socket_t *socket;
    uint64 timestamp;
    uint thread_id;
    
    if (!control_code_is_reported(control_code))
        return;
    
    NET_LOCK;
    if ((control_code == AFD_CONNECT) && (event == 0))
        socket_handle = (HANDLE) UINT_FIELD(input_data, 2);
    socket = (network_socket_t *) hashtable_lookup(socket_table, socket_handle);
    
    if (socket == NULL) {
        //if (control_code_is_recognized(control_code))
            NET_DET("SYS_DeviceIoControlFile: handle 0x%x skipped (0x%x-%s)\n", 
                socket_handle, control_code, control_code_string(control_code));
        NET_UNLOCK;
        return;
    }
    
    if (socket->event != event) {
        if (socket->event != NULL)
            hashtable_remove(socket_table, socket->event);
        hashtable_add(socket_table, event, socket);
    }
    NET_UNLOCK;
    
    call_stack_id = observe_call_stack(dcontext);
    timestamp = get_system_time_millis();
    thread_id = current_thread_id();
    
    socket->event = event;
    socket->status = status_block;
    socket->pending_data = NULL;
    
    if (p2int(socket->status) < 0x1000)
        CS_WARN("Strange status: "PX"\n", socket->status);

    NET_DET("SYS_DeviceIoControlFile(0x%x, 0x%x, 0x%x-%s) [0x%x]: ", socket->handle, socket->event, 
        control_code, control_code_string(control_code), result);
    
    if ((control_code != AFD_BIND) && (socket->src.port == 0))
        CS_WARN("No local port for socket 0x%x\n", socket->id);

    switch (control_code) {
        case AFD_BIND: {
            socket->src.ip = UINT_FIELD(output_data, 1);
            socket->src.port = USHORT_FIELD(output_data, 1);
            if (result == NT_STATUS_SUCCESS) {
                socket->state = SOCKET_BOUND;
                
                NET_DET("bind local port complete: "LINK"\n", SOCKET_LINK(socket));
                write_network_event(NET_BIND, NET_SUCCESS, &socket->src, NET_NONE, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->op = PENDING_BIND;
                socket->pending_data = output_data;
                
                NET_DET("bind local port pending at "PX".\n", output_data);
                write_network_event(NET_BIND, NET_PENDING, &socket->src, NET_NONE, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
        } break;
        case AFD_CONNECT: {
            socket->dst.ip = UINT_FIELD(input_data, 4);
            socket->dst.port = USHORT_FIELD(input_data, 7);
            if (result == NT_STATUS_SUCCESS) {
                socket->state = SOCKET_CONNECTED;
                
                NET_DET("complete: "LINK"\n", SOCKET_LINK(socket));
                write_network_event(NET_CONNECT, NET_SUCCESS, &socket->dst, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->op = PENDING_TCP_CONNECT;
                
                NET_DET("pending: "LINK"\n", SOCKET_LINK(socket));
                write_network_event(NET_CONNECT, NET_PENDING, &socket->dst, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
        } break;
        case AFD_CONNECT2: {
            socket->dst.ip = UINT_FIELD(output_data, 1);
            socket->dst.port = USHORT_FIELD(output_data, 1);
            if (result == NT_STATUS_SUCCESS) {
                socket->state = SOCKET_CONNECTED;
                
                NET_DET("complete: "LINK"\n", SOCKET_LINK(socket));
                write_network_event(NET_CONNECT, NET_SUCCESS, &socket->dst, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->op = PENDING_TCP_CONNECT;
                
                NET_DET("pending: "LINK"\n", SOCKET_LINK(socket));
                write_network_event(NET_CONNECT, NET_PENDING, &socket->dst, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
        } break;
        case AFD_PIPE_SOCKET: {
            HANDLE destination = (HANDLE) UINT_FIELD(input_data, 2);
            network_socket_t *destination_socket = hashtable_lookup(socket_table, destination);
            destination_socket->dst = socket->dst;
            destination_socket->src = socket->src;
            
            NET_DET("pipe to socket 0x%x: "LINK"\n", destination, SOCKET_LINK(socket));
            write_network_event(NET_CONNECT, NET_SUCCESS, &socket->dst, NET_TCP, 0, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case AFD_QUERY_SOCKET: {
            socket->dst.port = USHORT_FIELD(output_data, 3);
            socket->dst.ip = UINT_FIELD(output_data, 2);
            socket->state = SOCKET_CONNECTED;
            
            NET_DET("client connection accepted: "LINK"\n", SOCKET_LINK(socket));
            write_network_event(NET_CONNECT, NET_SUCCESS, &socket->dst, NET_TCP, 0, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case AFD_SEND: {
            NET_DET(LINK", ", SOCKET_LINK(socket));
            
            if (result == NT_STATUS_SUCCESS) {
                NET_DET("%d bytes sent\n", status_block->Information);
                write_network_event(NET_SEND, NET_SUCCESS, &empty_address, NET_TCP, status_block->Information, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->op = PENDING_TCP_SEND;
                socket->pending_data = input_data;
                
                NET_DET("pending...\n");
                write_network_event(NET_SEND, NET_PENDING, &empty_address, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
        } break;
        case AFD_RECV: {
            AFD_RECV_INFO *info = (AFD_RECV_INFO *) input_data;
            if (info->TdiFlags == (TDI_NORMAL | TDI_PEEK)) {
                NET_DET("skipping TDI peek.\n");
                return;
            }
            
            NET_DET("Data received from "LINK"; ", SOCKET_LINK(socket));
            if (result == NT_STATUS_SUCCESS) {
                NET_DET("data length %d\n", status_block->Information);
                write_network_event(NET_RECEIVE, NET_SUCCESS, &empty_address, NET_TCP, status_block->Information, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->op = PENDING_TCP_RECEIVE;
                socket->pending_data = (byte *) input_data;
                
                NET_DET("data pending...\n");
                write_network_event(NET_RECEIVE, NET_PENDING, &empty_address, NET_TCP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
            
            if (info->BufferCount > 1) {
                uint i;
                NET_DET("+\tFound %d buffers in AFD_RECV; buffer sizes: ", info->BufferCount);
                for (i = 0; i < info->BufferCount; i++)
                    NET_DET("%d, ", info->BufferArray[i].len);
                NET_DET("\n");
            }
            if (info->TdiFlags != TDI_NORMAL)
                CS_WARN("AFD_RECV with strange TdiFlags: 0x%x\n", info->TdiFlags);
        } break;
        case AFD_UDP_SEND: {
            uint *destination = (uint *) UINT_FIELD(input_data, 13);
            socket->dst.ip = *(destination + 1);
            socket->dst.port = USHORT_FIELD(destination, 1);
            
            NET_DET(LINK", data length %d bytes\n", 
                SOCKET_LINK(socket), status_block->Information);
            write_network_event(NET_SEND, NET_SUCCESS, &socket->dst, NET_UDP, status_block->Information, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case AFD_UDP_RECV: {
            if (result == NT_STATUS_SUCCESS) {
                uint sender_data = UINT_FIELD(input_data, 4);
                network_address_t sender;
                sender.ip = UINT_FIELD(sender_data, 1);
                sender.port = USHORT_FIELD(sender_data, 1);
                
                NET_DET("[%d.%d.%d.%d:%d], data length %d\n", 
                    SPLIT_IP(sender.ip), PORT(sender.port), status_block->Information);
                write_network_event(NET_RECEIVE, NET_SUCCESS, &sender, NET_UDP, status_block->Information, 
                    call_stack_id, socket->id, thread_id, timestamp);
            } else {
                socket->pending_data = (byte *) input_data;
                socket->op = PENDING_UDP_RECEIVE;
                
                NET_DET(", data pending...\n");
                write_network_event(NET_RECEIVE, NET_PENDING, &empty_address, NET_UDP, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
            }
        } break;
        case AFD_SELECT: {
            uint handle_count = UINT_FIELD(input_data, 2);
            NET_DET("%d handles\n", handle_count);
        } break;
        case AFD_ICMP: {
            uint *ip_address = (uint *) input_data;
            NET_DET(IP".\n", SPLIT_IP(*ip_address));
        } break;
        case AFD_SET_CONTEXT:
            NET_DET("\n");
            break;
        default: {
            /*
            uint i;
            NET_DET("\n+\tinput (%d): ", input_length);
            for (i = 0; i < input_length; i++)
                NET_DET("%08x ", ((uint*) input_data)[i]);
            NET_DET("\n+\toutput (%d): ", output_length);
            for (i = 0; i < output_length; i++)
                NET_DET("%08x ", ((uint*) output_data)[i]);
            */
            NET_DET("\n");
        } break;
    }
}

void
notify_wait_for_single_object(dcontext_t *dcontext, HANDLE event)
{
    network_socket_t *socket;
    NET_LOCK;
    socket = (network_socket_t *) hashtable_lookup(socket_table, event);
    NET_UNLOCK;
    
    if ((socket != NULL) && (socket->op != PENDING_NONE)) {
        if (p2int(socket->status) > 0x1000) {
            switch (socket->status->Status) {
                case NT_STATUS_SUCCESS: 
                    pending_operation_completed(dcontext, socket);
                    break;
                case NT_STATUS_PENDING:
                    NET_DET("+\tOperation still pending on event 0x%x\n", event);
                    break;
                case NT_STATUS_CONNECTION_REFUSED:
                    NET_DET("+\tConnection refused on event 0x%x\n", event);
                    break;
                default:
                    if (socket->dst.ip != 0) {
                        CS_WARN("+\tNot sure what happened in wait on event 0x%x: 0x%x\n", 
                            event, socket->status->Status);
                    }
                    break;
            }
        } else {
            CS_WARN("+\tNo status in wait on event 0x%x\n", event);
        }
    }
}

void
notify_wait_for_multiple_objects(dcontext_t *dcontext, uint result, uint handle_count, HANDLE *handles, bool wait_all)
{
    uint i;
    
    if (result == WAIT_TIMEOUT) {
        //for (i = 0; i < handle_count; i++)
        //    NET_DET("Wait timeout on 0x%x\n", handles[i]);
        return;
    }
    
    if ((result >= WAIT_OBJECT_0) && (result < (WAIT_OBJECT_0 + handle_count))) {
        if (wait_all) {
            for (i = 0; i < handle_count; i++) {
                network_socket_t *socket = hashtable_lookup(socket_table, handles[i]);
                if (socket != NULL)
                    pending_operation_completed(dcontext, socket);
            }
        } else {
            network_socket_t *socket = hashtable_lookup(socket_table, handles[result - WAIT_OBJECT_0]);
            if (socket != NULL)
                pending_operation_completed(dcontext, socket);
            
            for (i = ((result - WAIT_OBJECT_0) + 1); i < handle_count; i++) {
                socket = hashtable_lookup(socket_table, handles[i]);
                if (socket != NULL)
                    CS_WARN("Pending operation on handle 0x%x with event 0x%x may have completed.\n", socket->handle, socket->event);
            }
        }
    } else if ((result >= WAIT_ABANDONED_0) && (result < (WAIT_ABANDONED_0 + handle_count))) {
        if (wait_all) {
            for (i = 0; i < handle_count; i++) {
                network_socket_t *socket = hashtable_lookup(socket_table, handles[i]);
                if (socket != NULL)
                    CS_WARN("Wait abandoned on socket 0x%x with event 0x%x. What does it mean?\n", socket->handle, socket->event);
            }
        } else {
            network_socket_t *socket = hashtable_lookup(socket_table, handles[result - WAIT_OBJECT_0]);
            if (socket != NULL)
                CS_WARN("Wait abandoned on socket 0x%x with event 0x%x. What does it mean?\n", socket->handle, socket->event);
            
            for (i = ((result - WAIT_OBJECT_0) + 1); i < handle_count; i++) {
                socket = hashtable_lookup(socket_table, handles[i]);
                if (socket != NULL)
                    CS_WARN("Pending operation on handle 0x%x with event 0x%x may have been abandoned. What would it mean?\n", socket->handle, socket->event);
            }
        }
    }
}        

bool
socket_handle_remove(dcontext_t *dcontext, HANDLE handle)
{
    bool is_socket = false;
    
    NET_LOCK;
    {
        network_socket_t *socket = (network_socket_t *) hashtable_lookup(socket_table, handle);
        if (socket != NULL) {
            if (socket->handle == handle) {
                ushort call_stack_id = observe_call_stack(dcontext);
                uint64 timestamp = get_system_time_millis();
                uint thread_id = current_thread_id();
    
                NET_DET("Socket 0x%x closed.\n", socket->handle);
                write_network_event(NET_CLOSE, NET_SUCCESS, &empty_address, NET_NONE, 0, 
                    call_stack_id, socket->id, thread_id, timestamp);
                
                is_socket = true;
                
                hashtable_remove(socket_table, socket->event);
                hashtable_remove(socket_table, socket->handle);
                dr_global_free(socket, sizeof(network_socket_t));
            } else if (socket->event == handle) {
                NET_DET("Socket event 0x%x closed.\n", socket->handle);
                hashtable_remove(socket_table, socket->event);
                socket->event = NULL;
            } else {
                ASSERT(false);
            }
        }
    }
    NET_UNLOCK;
    
    return is_socket;
}

void
destroy_network_monitor()
{
    // cs-todo: will crash on exit with double-free if any sockets are left in the table
    socket_table->free_payload_func = network_socket_delete;
    hashtable_delete(socket_table);
    dr_global_free(socket_table, sizeof(hashtable_t));
    dr_mutex_destroy(socket_lock);
}

static void
network_socket_delete(void *socket)
{
    dr_global_free(socket, sizeof(network_socket_t));
}

static void
pending_operation_completed(dcontext_t *dcontext, network_socket_t *socket)
{
    ushort call_stack_id = observe_call_stack(dcontext);
    uint64 timestamp = get_system_time_millis();
    uint thread_id = current_thread_id();
    
    switch (socket->op) {
        case PENDING_BIND: {
            socket->src.ip = UINT_FIELD(socket->pending_data, 1);
            socket->src.port = USHORT_FIELD(socket->pending_data, 1);
            socket->pending_data = NULL;
            socket->state = SOCKET_BOUND;
            socket->op = PENDING_NONE;
            
            NET_DET("+\tBind successful: "LINK"\n", SOCKET_LINK(socket));
            write_network_event(NET_BIND, NET_SUCCESS, &socket->src, NET_NONE, 0, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case PENDING_TCP_CONNECT: {
            socket->state = SOCKET_CONNECTED;
            socket->op = PENDING_NONE;
            
            NET_DET("+\tConnection successful: "LINK"\n", SOCKET_LINK(socket));
            write_network_event(NET_CONNECT, NET_SUCCESS, &socket->dst, NET_TCP, 0, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case PENDING_TCP_SEND: {
            socket->pending_data = NULL;
            socket->op = PENDING_NONE;
            
            NET_DET("+\tSend successful: "LINK": %d bytes sent.\n", 
                SOCKET_LINK(socket), socket->status->Information);
            write_network_event(NET_SEND, NET_SUCCESS, &socket->dst, NET_TCP, socket->status->Information, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case PENDING_TCP_RECEIVE: {
            socket->pending_data = NULL;
            socket->op = PENDING_NONE;
            
            NET_DET("+\tTCP received from "LINK": %d bytes received\n", 
                SOCKET_LINK(socket), socket->status->Information);
            write_network_event(NET_RECEIVE, NET_SUCCESS, &socket->dst, NET_TCP, socket->status->Information, 
                call_stack_id, socket->id, thread_id, timestamp);
        } break;
        case PENDING_UDP_RECEIVE: {
            uint sender_data = UINT_FIELD(socket->pending_data, 4);
            network_address_t sender;
            sender.ip = UINT_FIELD(sender_data, 1);
            sender.port = USHORT_FIELD(sender_data, 1);
            
            NET_DET("+\tUDP received from [%d.%d.%d.%d:%d]: %d bytes received\n", 
                SPLIT_IP(sender.ip), PORT(sender.port), socket->status->Information);
            write_network_event(NET_RECEIVE, NET_SUCCESS, &sender, NET_UDP, socket->status->Information, 
                call_stack_id, socket->id, thread_id, timestamp);
            
            socket->pending_data = NULL;
            socket->op = PENDING_NONE;
        } break;
    }
}

static bool
control_code_is_recognized(IoControlCode code)
{
    switch (code) {
        case AFD_BIND:
        case AFD_CONNECT:
        case AFD_PIPE_SOCKET:
        case AFD_QUERY_SOCKET:
        case AFD_RECV: 
        case AFD_SEND: 
        case AFD_UDP_SEND:
        case AFD_UDP_RECV:
        case AFD_SELECT: 
        case AFD_SET_CONTEXT:
        case AFD_ICMP: 
            return true;
    }
    return false;
}

static bool
control_code_is_reported(IoControlCode code)
{
    switch (code) {
        case AFD_BIND:
        case AFD_CONNECT:
        case AFD_CONNECT2:
        case AFD_PIPE_SOCKET:
        case AFD_QUERY_SOCKET:
        case AFD_RECV: 
        case AFD_SEND: 
        case AFD_UDP_SEND:
        case AFD_UDP_RECV:
            return true;
    }
    return false;
}
