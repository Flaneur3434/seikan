--  WG_Handshake - C-callable WireGuard Handshake API
--
--  Thin C-exported wrappers around the Ada Handshake package.
--  These are the entry points called by C firmware code (udp_server.c)
--  to perform WireGuard Noise IK handshake operations.
--
--  Buffer management uses the shared Messages.Packet_Pool:
--    - TX path: Ada allocates buffer, builds message, returns address to C
--    - RX path: C passes received buffer address, Ada acquires and processes
--
--  C signatures:
--    bool     wg_init(void);
--    void    *wg_create_initiation(uint16_t *out_len);
--    void    *wg_handle_initiation(void *rx_buf, uint16_t *out_len);
--    bool     wg_handle_response(void *rx_buf);

with System;
with Interfaces;
with Interfaces.C;

package WG_Handshake
  with SPARK_Mode => Off
is
   use type Interfaces.C.C_bool;

   --  Initialize handshake subsystem.
   --  Loads keys from sdkconfig (via WG_Keys C bridge), computes
   --  derived keys, and initializes Identity + Peer.
   --  Must be called once before any handshake operations.
   --  Returns True on success.
   function Init return Interfaces.C.C_bool
     with Export, Convention => C, External_Name => "wg_init";

   --  Create a handshake initiation message (Initiator TX).
   --  Allocates a pool buffer, builds Message_Handshake_Initiation,
   --  and returns the buffer address for C to transmit.
   --  On success: returns wg_packet_t address, *Out_Len = message length.
   --  On failure: returns Null_Address, *Out_Len = 0.
   --  Caller must free the returned buffer via packet_pool_free().
   function Create_Initiation
     (Out_Len : access Interfaces.Unsigned_16) return System.Address
     with Export, Convention => C, External_Name => "wg_create_initiation";

   --  Handle a received initiation and create a response (Responder RX+TX).
   --  Acquires RX buffer from C, processes the initiation, creates a
   --  response in a new TX buffer, and frees the RX buffer.
   --  On success: returns wg_packet_t address of response, *Out_Len = length.
   --  On failure: returns Null_Address, frees RX buffer, *Out_Len = 0.
   --  Caller must free the returned buffer via packet_pool_free().
   function Handle_Initiation
     (RX_Buf  : System.Address;
      Out_Len : access Interfaces.Unsigned_16) return System.Address
     with Export, Convention => C, External_Name => "wg_handle_initiation";

   --  Handle a received response to complete the handshake (Initiator RX).
   --  Acquires RX buffer from C, processes the response, and frees it.
   --  Returns True if the handshake completed successfully.
   function Handle_Response
     (RX_Buf : System.Address) return Interfaces.C.C_bool
     with Export, Convention => C, External_Name => "wg_handle_response";

end WG_Handshake;
