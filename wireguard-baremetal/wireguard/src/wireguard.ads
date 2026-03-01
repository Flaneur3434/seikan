--  Wireguard - Top-Level C Interface
--
--  C is a dumb I/O driver.  All protocol intelligence lives in Ada.
--  C decides WHAT to send; Ada decides HOW.
--
--  RX path:
--    action = wg_receive_netif (rx_buf, &pt_len)
--    Ada processes the packet and returns an action code.
--    If transport data, Ada decrypts in-place in rx_buf (zero-copy).
--    On RX_Decryption_Success, C re-owns rx_buf with plaintext at offset 16.
--    C injects into lwIP via wg_netif_inject_plaintext() or echoes back.
--
--  TX path:
--    tx_buf = wg_send (peer, payload, len, &out_len)
--    C provides plaintext (or NULL/0 for keepalive).
--    Ada encrypts and returns a pool buffer ready for sendto().
--
--  Handshake:
--    tx_buf = wg_create_initiation (&out_len)
--    tx_buf = wg_create_response (&out_len)
--    C calls the appropriate function based on wg_receive's action.
--
--  Buffer ownership:
--    - wg_receive: Ada owns rx_buf (freed internally).
--    - wg_create_*, wg_send: C owns returned buffer, frees via tx_pool_free().

with System;
with Interfaces;
with Interfaces.C;

package Wireguard
  with SPARK_Mode => Off
is

   ---------------------------------------------------------------------------
   --  Action - What C should do after wg_receive
   ---------------------------------------------------------------------------

   type WG_Action is
     (Action_None,            --  Nothing to do (keepalive / response processed)
      Action_Send_Response,   --  Call wg_create_response, sendto, free
      RX_Decryption_Success,  --  Decrypted data in pt_out (C decides next step)
      Action_Error)           --  Processing failed
   with Convention => C;

   for WG_Action use
     (Action_None           => 0,
      Action_Send_Response  => 1,
      RX_Decryption_Success => 2,
      Action_Error          => 3);

   ---------------------------------------------------------------------------
   --  wg_init
   ---------------------------------------------------------------------------

   function Init return Interfaces.C.C_bool
   with Export, Convention => C, External_Name => "wg_init";

   ---------------------------------------------------------------------------
   --  wg_create_initiation - Build a handshake initiation
   --
   --  Allocates a TX pool buffer, builds the 148-byte initiation.
   --  C must free via tx_pool_free() after sendto().
   ---------------------------------------------------------------------------

   function Create_Initiation
     (Out_Len : access Interfaces.Unsigned_16) return System.Address
   with Export, Convention => C, External_Name => "wg_create_initiation";

   ---------------------------------------------------------------------------
   --  wg_create_response - Build a handshake response
   --
   --  Call ONLY after wg_receive returned Action_Send_Response.
   --  Builds the response from the handshake state set by wg_receive,
   --  derives transport keys, and activates the new session.
   --
   --  Allocates a TX pool buffer.
   --  C must free via tx_pool_free() after sendto().
   ---------------------------------------------------------------------------

   function Create_Response
     (Out_Len : access Interfaces.Unsigned_16) return System.Address
   with Export, Convention => C, External_Name => "wg_create_response";

   ---------------------------------------------------------------------------
   --  wg_send - Encrypt payload and return TX buffer
   --
   --  Generic outbound transport path.  Pass payload=NULL, len=0 for
   --  keepalive (32 bytes on wire).  C must free via tx_pool_free().
   ---------------------------------------------------------------------------

   function Send
     (Peer_ID     : Interfaces.C.unsigned;
      Payload     : System.Address;
      Payload_Len : Interfaces.Unsigned_16;
      Out_Len     : access Interfaces.Unsigned_16) return System.Address
   with Export, Convention => C, External_Name => "wg_send";

   ---------------------------------------------------------------------------
   --  wg_dispatch_timer — Ada-owned timer action dispatch
   --
   --  Called by the WG task after session_tick_all() returns a non-idle
   --  action for a peer.  Ada handles the full protocol sequence:
   --    Session_Expired / Rekey_Timed_Out → Expire_Session
   --    Initiate_Rekey → Create_Initiation + Set_Rekey_Flag
   --    Send_Keepalive → Build_And_Encrypt_TX (zero-length)
   --
   --  Returns a TX buffer + length if C needs to sendto().
   --  TX_Buf = Null_Address means no packet to send.
   ---------------------------------------------------------------------------

   procedure Dispatch_Timer
     (Peer   : Interfaces.C.unsigned;
      Action : Interfaces.Unsigned_8;
      TX_Buf : out System.Address;
      TX_Len : out Interfaces.Unsigned_16)
   with Export, Convention => C, External_Name => "wg_dispatch_timer";

   ---------------------------------------------------------------------------
   --  wg_auto_handshake — Rate-limited auto-initiation
   --
   --  Called by C when inner data is queued but no session exists.
   --  Ada rate-limits (Rekey_Timeout_S) and checks for in-flight handshake.
   --  Returns a TX buffer + length if C should sendto(),
   --  or Null_Address / 0 if rate-limited or already handshaking.
   ---------------------------------------------------------------------------

   procedure Auto_Handshake
     (Peer   : Interfaces.C.unsigned;
      TX_Buf : out System.Address;
      TX_Len : out Interfaces.Unsigned_16)
   with Export, Convention => C, External_Name => "wg_auto_handshake";

   ---------------------------------------------------------------------------
   --  wg_receive_netif - Process incoming packet, zero-copy RX path
   --
   --  Like wg_receive, but for transport data (type 4), Ada decrypts
   --  in-place and returns the RX pool buffer to C instead of copying
   --  plaintext to a stack buffer.
   --
   --  On WG_ACTION_RX_DECRYPTION_SUCCESS:
   --    Ada has returned the pool buffer to C ownership.
   --    Plaintext occupies rx_buf->data[Transport_Header_Size .. +pt_len-1].
   --    *pt_len = plaintext length.
   --    C must either inject via wg_netif_inject_plaintext (transfers
   --    ownership to lwIP) or call rx_pool_free(rx_buf) directly.
   --
   --  On Action_Send_Response / Action_None / Action_Error:
   --    Ada has freed the buffer.  C must NOT touch rx_buf.
   --    *pt_len = 0.
   ---------------------------------------------------------------------------

   function Receive_Netif
     (RX_Buf : System.Address;
      PT_Len : access Interfaces.Unsigned_16) return WG_Action
   with Export, Convention => C, External_Name => "wg_receive_netif";

end Wireguard;
