--  Wireguard - Top-level C interface implementation
--
--  Thin C-facing shim.  All protocol intelligence lives in
--  Wireguard.Protocol (SPARK_Mode => On).  This package converts
--  C types (System.Address, access params, C.unsigned) to Ada types
--  and delegates to Protocol operations.
--
--  State:
--    Initialized — C-facing guard, set once by Init

with Interfaces;   use Interfaces;
with Interfaces.C; use Interfaces.C;
with Utils;        use Utils;
with WG_Types;     use WG_Types;
with Crypto.KX;
with Messages;
with Session;
with Session.Timers;
with Timer.Clock;
with WG_Keys;
with Wireguard.Protocol;

package body Wireguard
  with SPARK_Mode => Off
is

   --  C_bool helpers
   C_True  : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (1);
   C_False : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (0);

   ---------------------------------------------------------------------------
   --  Package State
   ---------------------------------------------------------------------------

   Initialized : Boolean := False;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   function Init return C_bool is
      use type Interfaces.C.C_bool;

      Priv_Key  : Crypto.KX.Secret_Key;
      Peer_Keys : Wireguard.Protocol.Peer_Init_Array;
      Success   : Boolean;
   begin
      --  Load static private key from sdkconfig
      if WG_Keys.Get_Static_Private_Key (Priv_Key) = C_False then
         return C_False;
      end if;

      --  Load per-peer configuration from sdkconfig.
      --  Peer 1 is required; peer 2+ are optional (skipped if no key).
      for P in Session.Peer_Index loop
         declare
            C_Peer   : constant Interfaces.C.unsigned :=
              Interfaces.C.unsigned (P);
            Peer_Pub : Crypto.KX.Public_Key;
         begin
            if WG_Keys.Get_Peer_Public_Key (C_Peer, Peer_Pub) = C_True then
               Peer_Keys (P) :=
                 (Has_Key     => True,
                  Public_Key  => Peer_Pub,
                  Allowed_IP  =>
                    (Addr       =>
                       Interfaces.Unsigned_32
                         (WG_Keys.Get_Peer_Allowed_IP (C_Peer)),
                     Prefix_Len =>
                       Natural (WG_Keys.Get_Peer_Allowed_Prefix (C_Peer))),
                  Keepalive_S =>
                    Interfaces.Unsigned_64
                      (WG_Keys.Get_Peer_Keepalive (C_Peer)));
            else
               --  Peer 1 must have a key configured
               if P = 1 then
                  return C_False;
               end if;
               --  Optional peers left at default (Has_Key = False)
            end if;
         end;
      end loop;

      --  Packet pools are initialized from C (packet_pool_init) with
      --  statically-allocated semaphore handles before wg_init is called.

      --  Session table is initialized from C via wg_session_init()
      --  which creates the binary semaphore and calls Session.Init.
      --  That must be called before wg_init().

      Wireguard.Protocol.Init (Priv_Key, Peer_Keys, Success);
      Initialized := Success;

      return (if Initialized then C_True else C_False);
   end Init;

   ---------------------------------------------------------------------------
   --  Create_Initiation — Delegate to Protocol
   ---------------------------------------------------------------------------

   function Create_Initiation
     (Peer_ID : Interfaces.C.unsigned; Out_Len : access Unsigned_16)
      return System.Address
   is
      use System;

      P       : Session.Peer_Index;
      TX_Ptr  : C_Buffer_Ptr;
      TX_Len  : Messages.Packet_Length;
      Success : Boolean;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Validate peer index
      if Peer_ID
         not in Interfaces.C.unsigned (Session.Peer_Index'First)
              .. Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return Null_Address;
      end if;
      P := Session.Peer_Index (Peer_ID);

      Wireguard.Protocol.Create_Initiation (P, TX_Ptr, TX_Len, Success);
      if not Success then
         return Null_Address;
      end if;

      Out_Len.all := Unsigned_16 (TX_Len);
      return To_Address (TX_Ptr);
   end Create_Initiation;

   ---------------------------------------------------------------------------
   --  Create_Response — Delegate to Protocol
   ---------------------------------------------------------------------------

   function Create_Response
     (Out_Len : access Unsigned_16) return System.Address
   is
      use System;

      TX_Ptr  : C_Buffer_Ptr;
      TX_Len  : Messages.Packet_Length;
      Success : Boolean;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      Wireguard.Protocol.Create_Response (TX_Ptr, TX_Len, Success);
      if not Success then
         return Null_Address;
      end if;

      Out_Len.all := Unsigned_16 (TX_Len);
      return To_Address (TX_Ptr);
   end Create_Response;

   ---------------------------------------------------------------------------
   --  Send - Encrypt plaintext to be ready to send
   ---------------------------------------------------------------------------

   function Send
     (Peer_ID     : Interfaces.C.unsigned;
      Payload     : System.Address;
      Payload_Len : Interfaces.Unsigned_16;
      Out_Len     : access Unsigned_16) return System.Address
   is
      use System;

      Peer    : Session.Peer_Index;
      TX_Ptr  : Utils.C_Buffer_Ptr;
      Pkt_Len : Messages.Packet_Length;
      OK      : Boolean;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Validate peer index
      if Peer_ID
         not in Interfaces.C.unsigned (Session.Peer_Index'First)
              .. Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return Null_Address;
      end if;
      Peer := Session.Peer_Index (Peer_ID);

      --  Zero-length = keepalive, otherwise overlay caller's buffer
      if Payload_Len = 0 then
         declare
            Empty : constant Byte_Array (1 .. 0) := [others => 0];
         begin
            Wireguard.Protocol.Build_And_Encrypt_TX
              (Peer, Empty, TX_Ptr, Pkt_Len, OK);
            if not OK then
               return Null_Address;
            end if;
         end;
      else
         declare
            Data : Byte_Array (0 .. Natural (Payload_Len) - 1)
            with Import, Address => Payload;
         begin
            Wireguard.Protocol.Build_And_Encrypt_TX
              (Peer, Data, TX_Ptr, Pkt_Len, OK);
            if not OK then
               return Null_Address;
            end if;
            --  Track data-send timestamp (distinct from keepalive)
            --  for unresponsive peer detection (§6.5).
            Session.Mark_Data_Sent (Peer, Timer.Clock.Now);
         end;
      end if;

      Out_Len.all := Unsigned_16 (Pkt_Len);
      return Utils.To_Address (TX_Ptr);
   end Send;

   ---------------------------------------------------------------------------
   --  Auto_Handshake — Delegate to Protocol
   ---------------------------------------------------------------------------

   procedure Auto_Handshake
     (Peer   : Interfaces.C.unsigned;
      TX_Buf : out System.Address;
      TX_Len : out Interfaces.Unsigned_16)
   is
      P      : Session.Peer_Index;
      TX_Ptr : C_Buffer_Ptr;
      Pkt_Len : Messages.Packet_Length;
   begin
      TX_Buf := System.Null_Address;
      TX_Len := 0;

      if not Initialized then
         return;
      end if;

      --  Validate peer index
      if Peer
         not in Interfaces.C.unsigned (Session.Peer_Index'First)
              .. Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;
      P := Session.Peer_Index (Peer);

      Wireguard.Protocol.Auto_Handshake (P, TX_Ptr, Pkt_Len);
      if not Is_Null (TX_Ptr) then
         TX_Buf := To_Address (TX_Ptr);
         TX_Len := Unsigned_16 (Pkt_Len);
      end if;
   end Auto_Handshake;

   ---------------------------------------------------------------------------
   --  Dispatch_Timer — Ada-owned timer action dispatch
   --
   --  Replaces the C wg_session_action() function.  Protocol sequencing
   --  is now entirely in Ada; C only calls sendto() if we return a buffer.
   ---------------------------------------------------------------------------

   procedure Dispatch_Timer
     (Peer   : Interfaces.C.unsigned;
      Action : Interfaces.Unsigned_8;
      TX_Buf : out System.Address;
      TX_Len : out Interfaces.Unsigned_16)
   is
      use Session.Timers;
      use type System.Address;

      P          : Session.Peer_Index;
      Ada_Action : Timer_Action;
   begin
      TX_Buf := System.Null_Address;
      TX_Len := 0;

      --  Validate peer index
      if Peer
         not in Interfaces.C.unsigned (Session.Peer_Index'First)
              .. Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;
      P := Session.Peer_Index (Peer);

      --  Convert C uint8 → Ada Timer_Action enum
      if Action > Timer_Action'Pos (Timer_Action'Last) then
         return;
      end if;
      Ada_Action := Timer_Action'Val (Natural (Action));

      --  All timer actions (including Send_Keepalive) delegate to Protocol
      declare
         Ptr : Utils.C_Buffer_Ptr;
         PL  : Messages.Packet_Length;
      begin
         Wireguard.Protocol.Dispatch_Timer (P, Ada_Action, Ptr, PL);
         if not Utils.Is_Null (Ptr) then
            TX_Buf := Utils.To_Address (Ptr);
            TX_Len := Unsigned_16 (PL);
         end if;
      end;
   end Dispatch_Timer;

   ---------------------------------------------------------------------------
   --  Receive_Netif — Zero-copy-RX dispatch
   --
   --  Thin shim: delegates to Protocol.Dispatch_RX which acquires the
   --  buffer, dispatches, and releases back to C on success.
   ---------------------------------------------------------------------------

   function Receive_Netif
     (RX_Buf   : System.Address;
      PT_Len   : access Unsigned_16;
      Peer_Out : access Interfaces.C.unsigned) return WG_Action
   is
      Peer_Idx : Session.Peer_Index;
      Pkt_PT   : Messages.Packet_Length;
      Result   : WG_Action;
   begin
      PT_Len.all := 0;
      Peer_Out.all := 0;

      if not Initialized then
         return Action_Error;
      end if;

      declare
         RX_Ptr : Utils.C_Buffer_Ptr := From_Address (RX_Buf);
      begin
         Wireguard.Protocol.Dispatch_RX (RX_Ptr, Pkt_PT, Peer_Idx, Result);
      end;

      if Result = RX_Decryption_Success then
         PT_Len.all := Unsigned_16 (Pkt_PT);
      end if;

      Peer_Out.all := Interfaces.C.unsigned (Peer_Idx);
      return Result;
   end Receive_Netif;

end Wireguard;
