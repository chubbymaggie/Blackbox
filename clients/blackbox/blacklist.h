#ifndef BLACKLIST_H
#define BLACKLIST_H 1

void
init_blacklist();

void
delete_blacklist();

void
blacklist_bind_module(module_location_t *location);

void
blacklist_unbind_module(module_location_t *module);

void
check_blacklist_node(module_location_t *location, app_pc tag);

void
check_blacklist_edge(module_location_t *from_module, module_location_t *to_module, app_pc from, app_pc to,
                     bb_state_t *from_state, bb_state_t *to_state, bb_hash_t edge_hash, graph_edge_type edge_type);

#endif
