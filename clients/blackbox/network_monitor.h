#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H 1

typedef struct _network_address_t {
    uint ip;
    ushort port;
} network_address_t;

typedef enum _network_event_type_t {
    NET_BIND,
    NET_CONNECT,
    NET_SEND,
    NET_RECEIVE,
    NET_CLOSE
} network_event_type_t;

typedef enum _network_event_status_t {
    NET_PENDING,
    NET_SUCCESS,
    NET_FAILED
} network_event_status_t;

typedef enum _network_protocol_t {
    NET_NONE = 0,
    NET_TCP,
    NET_UDP,
    NET_ICMP
} network_protocol_t;

void
init_network_monitor();

void
notify_socket_created(HANDLE socket);

void
notify_device_io_control(dcontext_t *dcontext, uint result, HANDLE socket, HANDLE event, IO_STATUS_BLOCK *status_block, 
  IoControlCode control_code, byte *input_data, uint input_length, byte *output_data, uint output_length);

void
notify_wait_for_single_object(dcontext_t *dcontext, HANDLE event);

void
notify_wait_for_multiple_objects(dcontext_t *dcontext, uint result, uint handle_count, HANDLE *handles, bool wait_all);

bool
socket_handle_remove(dcontext_t *dcontext, HANDLE socket_handle);

void
destroy_network_monitor();

#endif
