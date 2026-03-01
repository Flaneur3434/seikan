/**
 * wg_peer_table.h — Peer table: AllowedIPs routing + endpoint (Ada FFI)
 *
 * Unified peer configuration table owned by Ada.  Replaces the C-side
 * s_peer_endpoints[] hack in wg_task.c and adds cryptokey routing.
 *
 * All peer indices are 1-based (Ada Session.Peer_Index).
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key size — must match Crypto.KX.Public_Key_Bytes (32) */
#define WG_PUBLIC_KEY_BYTES 32

/* Maximum AllowedIPs per peer — must match Ada Peer_Table.Max_Allowed_IPs */
#define WG_MAX_ALLOWED_IPS 2

/* --------------------------------------------------------------------
 * Public key configuration
 * -------------------------------------------------------------------- */

/**
 * Register a peer's static public key (32 bytes).
 * Core of cryptokey routing: maps a key to a peer index.
 *
 * @param peer  1-based peer index.
 * @param key   Pointer to 32-byte public key.
 */
void wg_peer_set_public_key(unsigned int peer, const uint8_t *key);

/**
 * Look up a peer by its static public key.
 *
 * @param key  Pointer to 32-byte public key.
 * @return     1-based peer index, or 0 if not found.
 */
unsigned int wg_peer_lookup_by_key(const uint8_t *key);

/* --------------------------------------------------------------------
 * AllowedIPs configuration (call at startup)
 * -------------------------------------------------------------------- */

/**
 * One AllowedIP prefix entry.
 */
typedef struct {
    uint32_t     addr;        /**< IPv4 prefix address (network byte order) */
    unsigned int prefix_len;  /**< Prefix length (0..32) */
} wg_allowed_ip_t;

/**
 * Set a peer's AllowedIPs (bulk).
 * Pass count=0 to clear, or count=1 for a single prefix.
 *
 * @param peer   1-based peer index.
 * @param ips    Array of AllowedIP entries.
 * @param count  Number of entries (0..WG_MAX_ALLOWED_IPS).
 */
void wg_peer_set_allowed_ips(unsigned int peer,
                             const wg_allowed_ip_t *ips,
                             unsigned int count);

/* --------------------------------------------------------------------
 * TX routing — longest prefix match
 * -------------------------------------------------------------------- */

/**
 * Look up which peer owns a destination IP.
 * Scans all peers' AllowedIPs for the longest matching prefix.
 *
 * @param dest_ip  Destination IPv4 address (network byte order).
 * @return         1-based peer index, or 0 if no match.
 */
unsigned int wg_peer_lookup_by_ip(uint32_t dest_ip);

/* --------------------------------------------------------------------
 * RX source filter — cryptokey routing validation
 * -------------------------------------------------------------------- */

/**
 * Check if an inner source IP is in a peer's AllowedIPs.
 * Per WireGuard §4: prevents spoofing from compromised peers.
 *
 * @param peer    1-based peer index.
 * @param src_ip  Inner source IPv4 address (network byte order).
 * @return        Non-zero if allowed, 0 if rejected.
 */
uint8_t wg_peer_check_source(unsigned int peer, uint32_t src_ip);

/* --------------------------------------------------------------------
 * Endpoint management
 * -------------------------------------------------------------------- */

/**
 * Update a peer's outer UDP endpoint.
 * Called after cryptographic authentication (§6.5).
 *
 * @param peer  1-based peer index.
 * @param addr  IPv4 address (network byte order).
 * @param port  UDP port (network byte order).
 */
void wg_peer_update_endpoint(unsigned int peer,
                             uint32_t addr, uint16_t port);

/**
 * Retrieve a peer's last known outer endpoint.
 *
 * @param peer      1-based peer index.
 * @param out_addr  Output: IPv4 address (network byte order).
 * @param out_port  Output: UDP port (network byte order).
 * @return          Non-zero if endpoint is valid, 0 if unknown.
 */
uint8_t wg_peer_get_endpoint(unsigned int peer,
                             uint32_t *out_addr, uint16_t *out_port);

#ifdef __cplusplus
}
#endif
