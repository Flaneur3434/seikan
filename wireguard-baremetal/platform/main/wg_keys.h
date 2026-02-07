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

/**
 * Decode the ESP32 static private key into `out`.
 * Returns true on success, false if the sdkconfig value is missing/invalid.
 */
bool wg_get_static_private_key(uint8_t out[WG_KEY_LEN]);

/**
 * Decode the peer (Python test side) public key into `out`.
 * Returns true on success, false if the sdkconfig value is missing/invalid.
 */
bool wg_get_peer_public_key(uint8_t out[WG_KEY_LEN]);

/**
 * Decode the optional pre-shared key into `out`.
 * Returns true if a PSK was configured, false if empty (out zeroed).
 */
bool wg_get_preshared_key(uint8_t out[WG_KEY_LEN]);

#endif /* WG_KEYS_H */
