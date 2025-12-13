/**
 * @file ipset.h
 * @brief IP Set Header
 */

#ifndef IPSET_H
#define IPSET_H

#include <stdint.h>
#include <stdbool.h>

enum ipset_type {
    IPSET_TYPE_HASH_IP,
    IPSET_TYPE_HASH_NET,
    IPSET_TYPE_HASH_IPPORT
};

int ipset_init(void);
int ipset_create(const char *name, enum ipset_type type, uint32_t max_entries);
int ipset_add_ip(const char *name, uint32_t ip);
int ipset_add_net(const char *name, uint32_t ip, uint8_t prefix);
int ipset_del_ip(const char *name, uint32_t ip);
int ipset_del_net(const char *name, uint32_t ip, uint8_t prefix);
bool ipset_test_ip(const char *name, uint32_t ip);
void ipset_flush(const char *name);
void ipset_print(const char *name);
void ipset_list_all(void);
void ipset_cleanup(void);

#endif /* IPSET_H */
