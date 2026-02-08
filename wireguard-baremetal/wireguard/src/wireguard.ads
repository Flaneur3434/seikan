--  Wireguard - Top-Level C Interface
--
--  Single entry point for all WireGuard protocol operations.
--  C sees only three functions and an action enum — no message types,
--  no handshake internals, no session keys.
--
--  RX path (network → Ada):
--    action = wg_receive (rx_buf, &tx_buf, &tx_len)
--    Ada takes ownership of rx_buf, inspects byte 0, dispatches to
--    handshake or transport, and optionally returns a TX buffer.
--
--  TX path (Ada → network):
--    action = wg_send (tx_buf, &tx_len)
--    Caller places plaintext in tx_buf at offset 16 (after headroom).
--    Ada encrypts in-place and returns the buffer ready to send.
--    (Not yet implemented — placeholder for when TUN is added.)
--
--  Buffer ownership:
--    - wg_receive: Ada owns rx_buf after the call (freed internally).
--      If a TX buffer is returned, C must free it via tx_pool_free().
--    - wg_send: Ada takes the TX buffer, encrypts, returns it.
--      C must free via tx_pool_free() after sendto().

with System;
with Interfaces;
with Interfaces.C;

package Wireguard
  with SPARK_Mode => Off
is

   ---------------------------------------------------------------------------
   --  Action - What C should do with the returned buffer
   ---------------------------------------------------------------------------

   type WG_Action is
     (Action_None,            --  Nothing to send (processed internally)
      Action_Send_Response,   --  Handshake reply: sendto() then free
      Action_Send_Transport,  --  Encrypted data:  sendto() then free
      Action_Error)           --  Processing failed, nothing to send
   with Convention => C;

   for WG_Action use
     (Action_None           => 0,
      Action_Send_Response  => 1,
      Action_Send_Transport => 2,
      Action_Error          => 3);

   ---------------------------------------------------------------------------
   --  wg_init - Initialize the WireGuard subsystem
   --
   --  Loads keys, initializes packet pools, resets state.
   --  Must be called once before wg_receive / wg_send.
   ---------------------------------------------------------------------------

   function Init return Interfaces.C.C_bool
   with Export, Convention => C, External_Name => "wg_init";

   ---------------------------------------------------------------------------
   --  wg_receive - Process an incoming packet
   --
   --  Ada takes ownership of RX_Buf (freed internally).
   --  On Action_Send_Response or Action_Send_Transport:
   --    TX_Buf receives a pool buffer address for C to sendto().
   --    TX_Len receives the number of valid bytes.
   --    C must free via tx_pool_free() after sending.
   --  On Action_None or Action_Error:
   --    TX_Buf = NULL, TX_Len = 0.
   ---------------------------------------------------------------------------

   function Receive
     (RX_Buf : System.Address;
      TX_Buf : access System.Address;
      TX_Len : access Interfaces.Unsigned_16) return WG_Action
   with Export, Convention => C, External_Name => "wg_receive";

   ---------------------------------------------------------------------------
   --  wg_create_initiation - Trigger an ESP32-initiated handshake
   --
   --  Allocates a TX pool buffer, builds the 148-byte initiation.
   --  On success: returns buffer address, *Out_Len = 148.
   --  On failure: returns Null_Address, *Out_Len = 0.
   --  C must free the returned buffer via tx_pool_free().
   ---------------------------------------------------------------------------

   function Create_Initiation
     (Out_Len : access Interfaces.Unsigned_16) return System.Address
   with Export, Convention => C, External_Name => "wg_create_initiation";

end Wireguard;
