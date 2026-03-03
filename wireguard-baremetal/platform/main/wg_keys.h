/**
 * wg_keys.h - WireGuard key storage bridge
 *
 * Reads hex-encoded keys from sdkconfig (CONFIG_WG_*) and provides
 * C functions that decode them into raw 32-byte buffers.
 *
 * Ada imports these via pragma Import to get key material at startup.
 */

#ifndef WG_KEYS_H
#define WG_KEYS_H

#include <stdint.h>
#include <stdbool.h>

#define WG_KEY_LEN 32

/* ── Key loading ─────────────────────────────────────────────────── */

/**
 * Decode the ESP32 static private key into `out`.
 * Returns true on success, false if the sdkconfig value is missing/invalid.
 */
bool wg_get_static_private_key(uint8_t out[WG_KEY_LEN]);

/* ── Per-peer configuration ──────────────────────────────────────── */

/**
 * Decode a peer's public key into `out`.
 * @param peer  1-based peer index
 * @return true on success, false if not configured or empty
 */
bool wg_get_peer_public_key(unsigned int peer, uint8_t out[WG_KEY_LEN]);

/**
 * Decode a peer's optional pre-shared key into `out`.
 * @param peer  1-based peer index
 * @return true if a PSK was configured, false if empty (out zeroed)
 */
bool wg_get_peer_preshared_key(unsigned int peer, uint8_t out[WG_KEY_LEN]);

/**
 * Get a peer's AllowedIP address as host-byte-order uint32.
 * @param peer  1-based peer index
 * @return IPv4 address in host byte order, 0 if not configured
 */
uint32_t wg_get_peer_allowed_ip(unsigned int peer);

/**
 * Get a peer's AllowedIP prefix length.
 * @param peer  1-based peer index
 * @return prefix length 0..32
 */
uint8_t wg_get_peer_allowed_prefix(unsigned int peer);

/**
 * Get a peer's persistent keepalive interval.
 * @param peer  1-based peer index
 * @return keepalive interval in seconds, 0 = disabled
 */
uint16_t wg_get_peer_keepalive(unsigned int peer);

#endif /* WG_KEYS_H */
