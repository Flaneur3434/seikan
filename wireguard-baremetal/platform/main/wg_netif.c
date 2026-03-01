/**
 * @file wg_netif.c
 * @brief lwIP network interface for the WireGuard tunnel (wg0).
 *
 * Architecture overview
 * ─────────────────────
 * Outer (Internet-facing) side
 *   UDP PCB bound to port 51820.  Receives encrypted WireGuard datagrams,
 *   copies them into pool buffers, and enqueues to g_wg_rx_queue for
 *   wg_task to decrypt.
 *
 * Inner (tunnel) side — struct netif "wg0"
 *   lwIP routes IP traffic destined for the peer via the wg0 netif.
 *   The netif output callback copies the plaintext IP packet into a pool
 *   buffer at offset WG_TRANSPORT_HEADER_SIZE (16 bytes headroom for the
 *   WireGuard transport header), then enqueues to g_wg_inner_queue.
 *   wg_task calls wg_send() which encrypts in-place and returns the
 *   same pool buffer ready to transmit.
 *
 * Zero-copy TX (encrypted -> outer UDP)
 *   wg_netif_send_outer() wraps the pool buffer in a pbuf_custom/PBUF_REF
 *   so lwIP can call udp_sendto() without copying the payload.
 *   The custom_free callback calls tx_pool_free() once lwIP is done.
 *   Callers MUST NOT free the buffer themselves after a successful call.
 *
 * Zero-copy RX (decrypted -> lwIP stack)
 *   wg_netif_inject_plaintext() wraps the RX pool buffer in a
 *   pbuf_custom/PBUF_REF pointing to buf->data[pt_offset..pt_offset+pt_len-1].
 *   tcpip_input() hands it to lwIP from the wg_task context (thread-safe).
 *   The custom_free callback calls rx_pool_free() once lwIP is done.
 *   Callers MUST NOT free the buffer themselves after a successful call.
 */

#include "wg_netif.h"

#include <string.h>

#include <esp_log.h>

#include <lwip/ip_addr.h>
#include <lwip/ip4_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/udp.h>
#include <lwip/inet.h>
#include <lwip/def.h>
#include <lwip/tcpip.h>

#include "packet_pool.h"
#include "wg_task.h"
#include "wg_peer_table.h"
#include "wireguard.h"

#define WG_PORT          51820
#define WG_INNER_MTU     1420
#define WG_HEADER_OFFSET WG_TRANSPORT_HEADER_SIZE  /* 16 */

static const char *TAG = "wg_netif";

/* ---- Static state ------------------------------------------------------- */

static struct netif     s_wg_netif;
static struct udp_pcb  *s_outer_pcb;

/* ---- pbuf_custom wrappers -----------------------------------------------
 *
 * Two small static pools of wrapper structs — one for TX (encrypted
 * outgoing) and one for RX (decrypted incoming).  Each slot holds a
 * pbuf_custom header plus a back-pointer to the pool buffer so the
 * custom_free callback can return it.
 *
 * Pool depth matches the underlying packet pool depth (4 each), so
 * allocation cannot fail while pool buffers are available.
 * ----------------------------------------------------------------------- */

#define PBUF_WRAPPER_DEPTH 4

typedef struct {
    struct pbuf_custom pc;       /* MUST be first - pbuf_free() casts to this */
    packet_buffer_t   *pool_buf;
    bool               in_use;
} wg_tx_pbuf_t;

typedef struct {
    struct pbuf_custom pc;
    packet_buffer_t   *pool_buf;
    bool               in_use;
} wg_rx_pbuf_t;

static wg_tx_pbuf_t s_tx_wrappers[PBUF_WRAPPER_DEPTH];
static wg_rx_pbuf_t s_rx_wrappers[PBUF_WRAPPER_DEPTH];

/* Allocate a TX wrapper slot.  Called from wg_task context only. */
static wg_tx_pbuf_t *tx_wrapper_alloc(void)
{
    for (int i = 0; i < PBUF_WRAPPER_DEPTH; i++) {
        if (!s_tx_wrappers[i].in_use) {
            s_tx_wrappers[i].in_use = true;
            return &s_tx_wrappers[i];
        }
    }
    return NULL;
}

/* Allocate an RX wrapper slot.  Called from wg_task context only. */
static wg_rx_pbuf_t *rx_wrapper_alloc(void)
{
    for (int i = 0; i < PBUF_WRAPPER_DEPTH; i++) {
        if (!s_rx_wrappers[i].in_use) {
            s_rx_wrappers[i].in_use = true;
            return &s_rx_wrappers[i];
        }
    }
    return NULL;
}

/* pbuf_custom free callbacks - called by lwIP when it is done with the pbuf */

static void tx_custom_free(struct pbuf *p)
{
    wg_tx_pbuf_t *wp = (wg_tx_pbuf_t *)p;
    tx_pool_free(wp->pool_buf);
    wp->pool_buf = NULL;
    wp->in_use   = false;
}

static void rx_custom_free(struct pbuf *p)
{
    wg_rx_pbuf_t *wp = (wg_rx_pbuf_t *)p;
    rx_pool_free(wp->pool_buf);
    wp->pool_buf = NULL;
    wp->in_use   = false;
}

/* ---- wg0 netif callbacks ------------------------------------------------
 *
 * wg_netif_output: called by lwIP when it wants to send an IP packet via wg0.
 *
 * Copy the IP payload into a TX pool buffer at offset WG_HEADER_OFFSET so
 * that wg_task's wg_send() can write the WireGuard transport header into
 * those first 16 bytes and encrypt the whole thing in-place without moving
 * any data.  The buffer is then handed to wg_task via g_wg_inner_queue.
 * ----------------------------------------------------------------------- */

static err_t wg_netif_output(struct netif *netif,
                              struct pbuf *p,
                              const ip4_addr_t *ipaddr)
{
    (void)netif;
    (void)ipaddr;

    if (p == NULL) {
        return ERR_ARG;
    }

    size_t cap = packet_pool_get_buffer_size();
    if ((size_t)p->tot_len + WG_HEADER_OFFSET > cap) {
        ESP_LOGW(TAG, "wg0 output too large: %u + %u > %u",
                 (unsigned)p->tot_len, WG_HEADER_OFFSET, (unsigned)cap);
        return ERR_MEM;
    }

    packet_buffer_t *buf = tx_pool_allocate();
    if (buf == NULL) {
        ESP_LOGW(TAG, "TX pool exhausted for wg0 output");
        return ERR_MEM;
    }

    /* Copy IP packet to offset 16 - leave headroom for WG transport header */
    uint16_t copied = pbuf_copy_partial(p, buf->data + WG_HEADER_OFFSET,
                                        p->tot_len, 0);
    if (copied != p->tot_len) {
        tx_pool_free(buf);
        return ERR_BUF;
    }

    buf->len = (uint16_t)(WG_HEADER_OFFSET + p->tot_len);

    /* Cryptokey routing: determine which peer owns this destination IP.
     * IPv4 destination address is at offset 16 in the IP header.
     * Peer_Table stores AllowedIPs in host byte order, so we convert
     * the network-byte-order address from the packet header. */
    uint32_t dest_ip_nbo;
    memcpy(&dest_ip_nbo, buf->data + WG_HEADER_OFFSET + 16,
           sizeof(dest_ip_nbo));
    unsigned int peer = wg_peer_lookup_by_ip(ntohl(dest_ip_nbo));
    if (peer == 0) {
        /* No peer's AllowedIPs covers this destination — drop */
        tx_pool_free(buf);
        return ERR_RTE;
    }

    wg_inner_msg_t msg = {
        .buf      = buf,
        .pt_len   = p->tot_len,
        .peer_idx = (uint16_t)peer,
    };

    if (xQueueSend(g_wg_inner_queue, &msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "Inner queue full - dropping wg0 packet");
        tx_pool_free(buf);
        return ERR_MEM;
    }

    return ERR_OK;
}

static err_t wg_netif_init_cb(struct netif *netif)
{
    netif->name[0]    = 'w';
    netif->name[1]    = 'g';
    netif->output     = wg_netif_output;
    netif->linkoutput = NULL;
    netif->mtu        = WG_INNER_MTU;
    netif->flags      = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

/* ---- Outer UDP receive callback -----------------------------------------
 *
 * Called by lwIP when a UDP datagram arrives on port 51820.
 * Copies into an RX pool buffer and enqueues to g_wg_rx_queue for wg_task.
 * ----------------------------------------------------------------------- */

static void outer_recv_cb(void *arg,
                           struct udp_pcb *pcb,
                           struct pbuf *p,
                           const ip_addr_t *addr,
                           u16_t port)
{
    (void)arg;
    (void)pcb;

    if (p == NULL || addr == NULL) {
        if (p != NULL) pbuf_free(p);
        return;
    }

    if (!IP_IS_V4(addr)) {
        ESP_LOGW(TAG, "IPv6 outer packet - not supported");
        pbuf_free(p);
        return;
    }

    size_t cap = packet_pool_get_buffer_size();
    if ((size_t)p->tot_len > cap) {
        ESP_LOGW(TAG, "Outer packet too large: %u > %u",
                 (unsigned)p->tot_len, (unsigned)cap);
        pbuf_free(p);
        return;
    }

    packet_buffer_t *rx = rx_pool_allocate();
    if (rx == NULL) {
        ESP_LOGW(TAG, "RX pool exhausted");
        pbuf_free(p);
        return;
    }

    uint16_t pkt_len = p->tot_len;
    uint16_t copied  = pbuf_copy_partial(p, rx->data, pkt_len, 0);
    pbuf_free(p);

    if (copied != pkt_len) {
        rx_pool_free(rx);
        return;
    }

    rx->len = copied;

    struct sockaddr_in peer = {0};
    peer.sin_family         = AF_INET;
    peer.sin_port           = lwip_htons(port);
    peer.sin_addr.s_addr    = ip4_addr_get_u32(ip_2_ip4(addr));

    wg_rx_msg_t rx_msg = {
        .rx_buf = rx,
        .peer   = peer,
    };

    if (xQueueSend(g_wg_rx_queue, &rx_msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "RX queue full - dropping outer packet");
        rx_pool_free(rx);
    }
}

/* ---- Public API --------------------------------------------------------- */

bool wg_netif_init(void)
{
    ip4_addr_t ip, netmask, gw;

    IP4_ADDR(&ip,      10,  0, 0, 2);
    IP4_ADDR(&netmask, 255, 255, 255, 0);
    IP4_ADDR(&gw,      0,   0, 0, 0);

    if (netif_add(&s_wg_netif, &ip, &netmask, &gw,
                  NULL, wg_netif_init_cb, ip_input) == NULL) {
        ESP_LOGE(TAG, "Failed to add wg0 netif");
        return false;
    }

    netif_set_up(&s_wg_netif);

    s_outer_pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    if (s_outer_pcb == NULL) {
        ESP_LOGE(TAG, "Failed to create outer UDP pcb");
        return false;
    }

    if (udp_bind(s_outer_pcb, IP_ANY_TYPE, WG_PORT) != ERR_OK) {
        ESP_LOGE(TAG, "Failed to bind outer UDP pcb to port %d", WG_PORT);
        udp_remove(s_outer_pcb);
        s_outer_pcb = NULL;
        return false;
    }

    udp_recv(s_outer_pcb, outer_recv_cb, NULL);

    ESP_LOGI(TAG, "wg0 netif (10.0.0.2/24) + UDP :%d initialized", WG_PORT);
    return true;
}

bool wg_netif_start(void)
{
    /* Hook point for future bring-up logic */
    return true;
}

/**
 * wg_netif_send_outer - transmit an encrypted WireGuard packet.
 *
 * Wraps tx_buf in a PBUF_REF/pbuf_custom so udp_sendto() can read directly
 * from the pool buffer without copying.  On success, ownership of tx_buf
 * is transferred to the pbuf_custom callback (tx_custom_free -> tx_pool_free).
 * The caller MUST NOT free tx_buf after a successful return.
 * On failure the caller retains ownership and must free tx_buf itself.
 *
 * @param tx_buf  TX pool buffer.  data[0..tx_len-1] holds the ciphertext.
 * @param tx_len  Encrypted packet length.
 * @param peer    Destination endpoint.
 * @return true on success (ownership transferred), false on failure.
 */
bool wg_netif_send_outer(packet_buffer_t *tx_buf,
                          uint16_t tx_len,
                          const struct sockaddr_in *peer)
{
    if (s_outer_pcb == NULL || tx_buf == NULL || peer == NULL || tx_len == 0) {
        return false;
    }

    wg_tx_pbuf_t *wp = tx_wrapper_alloc();
    if (wp == NULL) {
        ESP_LOGW(TAG, "TX pbuf wrapper pool exhausted");
        return false;
    }

    wp->pool_buf                = tx_buf;
    wp->pc.custom_free_function = tx_custom_free;

    /* PBUF_RAW: offset=0, so payload points directly at tx_buf->data[0].
     * The WireGuard packet is already fully built; udp_sendto() prepends
     * UDP/IP/Ethernet headers from lwIP's own memory, not ours. */
    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, tx_len, PBUF_REF,
                                         &wp->pc,
                                         tx_buf->data, tx_len);
    if (p == NULL) {
        wp->in_use = false;
        ESP_LOGE(TAG, "custom alloc failed");
        return false;
    }

    /* Build destination ip_addr_t from sockaddr_in (network byte order) */
    ip_addr_t dst;
    IP_SET_TYPE_VAL(dst, IPADDR_TYPE_V4);
    ip4_addr_set_u32(ip_2_ip4(&dst), peer->sin_addr.s_addr);

    err_t err = udp_sendto(s_outer_pcb, p, &dst, lwip_ntohs(peer->sin_port));

    /* pbuf_free decrements the refcount.  When it hits zero lwIP calls
     * tx_custom_free which returns the pool buffer. */
    pbuf_free(p);

    if (err != ERR_OK) {
        ESP_LOGW(TAG, "udp_sendto failed: %d", (int)err);
        return false;
    }

    return true;
}

/**
 * wg_netif_inject_plaintext - inject a decrypted IP packet into lwIP.
 *
 * Called from wg_task after wg_receive_netif() returns
 * WG_ACTION_RX_DECRYPTION_SUCCESS.  Wraps the pool buffer in a
 * PBUF_REF/pbuf_custom pointing to the plaintext region, then calls
 * tcpip_input() (thread-safe) to deliver it to the wg0 netif.
 *
 * On success, ownership of rx_buf is transferred to the pbuf_custom
 * callback (rx_custom_free -> rx_pool_free).
 * The caller MUST NOT free rx_buf after a successful return.
 * On failure the caller retains ownership.
 *
 * @param rx_buf    RX pool buffer from wg_receive_netif().
 * @param pt_offset Byte offset inside rx_buf->data where plaintext starts
 *                  (always WG_TRANSPORT_HEADER_SIZE = 16).
 * @param pt_len    Plaintext byte count.
 * @return true on success (ownership transferred), false on failure.
 */
bool wg_netif_inject_plaintext(packet_buffer_t *rx_buf,
                                uint16_t pt_offset,
                                uint16_t pt_len)
{
    if (rx_buf == NULL || pt_len == 0) {
        return false;
    }

    if ((size_t)pt_offset + pt_len > packet_pool_get_buffer_size()) {
        ESP_LOGE(TAG, "inject_plaintext: offset+len %u+%u out of buffer",
                 pt_offset, pt_len);
        return false;
    }

    wg_rx_pbuf_t *wp = rx_wrapper_alloc();
    if (wp == NULL) {
        ESP_LOGW(TAG, "RX pbuf wrapper pool exhausted");
        return false;
    }

    wp->pool_buf                = rx_buf;
    wp->pc.custom_free_function = rx_custom_free;

    struct pbuf *p = pbuf_alloced_custom(PBUF_RAW, pt_len, PBUF_REF,
                                         &wp->pc,
                                         rx_buf->data + pt_offset, pt_len);
    if (p == NULL) {
        wp->in_use = false;
        return false;
    }

    /* tcpip_input() is the thread-safe entry point when called from a
     * non-lwIP task (wg_task).  It posts a message to the tcpip thread
     * so the pbuf is processed in the correct context. */
    err_t err = tcpip_input(p, &s_wg_netif);
    if (err != ERR_OK) {
        /* tcpip_input failed before taking ownership - pbuf_free will
         * invoke rx_custom_free and return rx_buf to the pool. */
        pbuf_free(p);
        ESP_LOGW(TAG, "tcpip_input failed: %d", (int)err);
        return false;
    }

    return true;
}
