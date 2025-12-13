/**
 * @file ppp_debug.h
 * @brief PPP Debug Logging API
 */

#ifndef PPP_DEBUG_H
#define PPP_DEBUG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Debug flags */
#define PPP_DEBUG_LCP       0x01
#define PPP_DEBUG_IPCP      0x02
#define PPP_DEBUG_PAP       0x04
#define PPP_DEBUG_CHAP      0x08
#define PPP_DEBUG_PPPOE     0x10
#define PPP_DEBUG_PACKET    0x20
#define PPP_DEBUG_ALL       0xFF

/**
 * Initialize debug subsystem
 */
void ppp_debug_init(void);

/**
 * Cleanup debug subsystem
 */
void ppp_debug_cleanup(void);

/**
 * Set debug flags
 */
void ppp_debug_set_flags(uint32_t flags);

/**
 * Set debug output file (NULL for stderr)
 */
void ppp_debug_set_file(const char *filename);

/**
 * LCP debug message
 */
void ppp_debug_lcp(const char *fmt, ...);

/**
 * IPCP debug message
 */
void ppp_debug_ipcp(const char *fmt, ...);

/**
 * PAP debug message
 */
void ppp_debug_pap(const char *fmt, ...);

/**
 * CHAP debug message
 */
void ppp_debug_chap(const char *fmt, ...);

/**
 * PPPoE debug message
 */
void ppp_debug_pppoe(const char *fmt, ...);

/**
 * Packet hex dump
 */
void ppp_debug_packet(uint16_t session_id, const char *direction,
                      const uint8_t *data, size_t len);

#endif /* PPP_DEBUG_H */
