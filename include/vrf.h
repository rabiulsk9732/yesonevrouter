/**
 * @file vrf.h
 * @brief VRF Header
 */

#ifndef VRF_H
#define VRF_H

#include <stdint.h>
#include <stdbool.h>

struct vrf;
struct routing_table;

int vrf_init(void);
struct vrf *vrf_create(const char *name, uint32_t id);
struct vrf *vrf_lookup(const char *name);
struct vrf *vrf_lookup_by_id(uint32_t id);
struct vrf *vrf_get_default(void);
int vrf_bind_interface(struct vrf *v, uint32_t ifindex);
struct routing_table *vrf_get_table(struct vrf *v);
void vrf_set_rd(struct vrf *v, uint64_t rd);
void vrf_print(void);
void vrf_cleanup(void);

#endif /* VRF_H */
