/**
 * @file pppoe_security.h
 * @brief PPPoE Security Module API
 */

#ifndef PPPOE_SECURITY_H
#define PPPOE_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include <rte_ether.h>

/**
 * Initialize security module
 */
int pppoe_security_init(void);

/**
 * Cleanup security module
 */
void pppoe_security_cleanup(void);

/**
 * Check PADI rate limit (anti-flood)
 * @return true if allowed, false if rate limited
 */
bool pppoe_security_check_padi(const struct rte_ether_addr *src_mac);

/**
 * Bind session to MAC and IP
 */
void pppoe_security_bind_session(uint16_t session_id, const struct rte_ether_addr *mac, uint32_t ip);

/**
 * Unbind session
 */
void pppoe_security_unbind_session(uint16_t session_id);

/**
 * Validate session packet (MAC binding + IP spoof detection)
 * @return true if valid, false if hijack/spoof detected
 */
bool pppoe_security_validate_packet(uint16_t session_id, const struct rte_ether_addr *src_mac, uint32_t src_ip);

/**
 * Configure security settings
 */
void pppoe_security_config(uint32_t padi_limit, uint32_t session_limit);

/**
 * Enable/disable security
 */
void pppoe_security_enable(bool enable);

/**
 * Get security statistics
 */
void pppoe_security_stats(uint32_t *padi_count, uint32_t *blocked_count);

#endif /* PPPOE_SECURITY_H */
