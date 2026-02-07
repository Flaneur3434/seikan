/**
 * wg_keys.c - WireGuard key storage bridge
 *
 * Decodes hex-encoded keys from sdkconfig.h (CONFIG_WG_*) into raw bytes.
 * Ada calls these via pragma Import to load key material at startup.
 */

#include "wg_keys.h"
#include "sdkconfig.h"
#include <string.h>

/* ── Hex decode ─────────────────────────────────────────────────────── */

/**
 * Decode a single hex character to its 4-bit value.
 * Returns -1 on invalid input.
 */
static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * Decode `hex_len` hex characters from `hex` into `out`.
 * `out` must have room for hex_len/2 bytes.
 * Returns true on success, false on invalid hex or wrong length.
 */
static bool hex_decode(const char *hex, uint8_t *out, size_t out_len)
{
    if (hex == NULL) return false;

    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return false;

    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_nibble(hex[i * 2]);
        int lo = hex_nibble(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

/* ── Public API ─────────────────────────────────────────────────────── */

bool wg_get_static_private_key(uint8_t out[WG_KEY_LEN])
{
#ifdef CONFIG_WG_STATIC_PRIVATE_KEY
    return hex_decode(CONFIG_WG_STATIC_PRIVATE_KEY, out, WG_KEY_LEN);
#else
    memset(out, 0, WG_KEY_LEN);
    return false;
#endif
}

bool wg_get_peer_public_key(uint8_t out[WG_KEY_LEN])
{
#ifdef CONFIG_WG_PEER_PUBLIC_KEY
    return hex_decode(CONFIG_WG_PEER_PUBLIC_KEY, out, WG_KEY_LEN);
#else
    memset(out, 0, WG_KEY_LEN);
    return false;
#endif
}

bool wg_get_preshared_key(uint8_t out[WG_KEY_LEN])
{
#ifdef CONFIG_WG_PRESHARED_KEY
    const char *hex = CONFIG_WG_PRESHARED_KEY;
    if (hex[0] == '\0') {
        /* Empty string → no PSK, zero out */
        memset(out, 0, WG_KEY_LEN);
        return false;
    }
    return hex_decode(hex, out, WG_KEY_LEN);
#else
    memset(out, 0, WG_KEY_LEN);
    return false;
#endif
}
