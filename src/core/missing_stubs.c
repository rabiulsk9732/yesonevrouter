/**
 * @file missing_stubs.c
 * @brief Truly minimal stubs - only functions with no implementation anywhere
 */

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* ========== HA Module ========== */
/* HA module is not linked, so all HA functions needed here */

struct ha_config {
    int mode;
    uint32_t local_ip;
    uint32_t peer_ip;
    uint32_t vip_ip;
    uint32_t vip_mask;
    char vip_iface[32];
    int state;
};

struct ha_config g_ha_config = {0};

int ha_init(uint32_t local_ip, uint32_t peer_ip) {
    g_ha_config.local_ip = local_ip;
    g_ha_config.peer_ip = peer_ip;
    return 0;
}

int ha_send_sync(uint8_t type, uint16_t session_id, const uint8_t *mac, uint32_t ip, uint8_t state) {
    (void)type; (void)session_id; (void)mac; (void)ip; (void)state;
    return 0;
}

void ha_poll(void) { }
void ha_check_failover(void) { }

/* ========== DHCPv6-PD ========== */

static struct { uint64_t requests; } stub_dhcp_stats = {0};
void* dhcpv6pd_get_stats(void) { return &stub_dhcp_stats; }
bool dhcpv6pd_is_enabled(void) { return false; }
void dhcpv6pd_dump_leases(void) { printf("DHCPv6-PD: No leases\n"); }
int dhcpv6pd_enable(bool e) { (void)e; return 0; }

/* Service Profile functions are now in src/pppoe/service_profile.c */
