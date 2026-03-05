--  Wireguard - Top-level C interface implementation
--
--  All WireGuard protocol intelligence lives here. C only does I/O.
--
--  State:
--    My_Identity, My_Peer  — loaded once in Init
--    HS_State              — ephemeral, wiped after session derivation
--    Session state         — managed by Session module (Keypair slots)
--    Timer state           — managed by Session.Timer (evaluated by tick)

with Interfaces;   use Interfaces;
with Interfaces.C; use Interfaces.C;
with Utils;        use Utils;
with WG_Types;     use WG_Types;
with Crypto.AEAD;
with Crypto.KX;
with Handshake;
with Messages;
with Session;
with Session.Timers;
with Timer.Clock;
with Peer_Table;
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

   My_Identity : Handshake.Static_Identity;
   Initialized : Boolean := False;

   --  Per-peer state arrays (indexed by Session.Peer_Index = 1..Max_Peers)
   My_Peers : array (Session.Peer_Index) of Handshake.Peer_Config;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   function Init return C_bool is
      use type Interfaces.C.C_bool;
      use type Interfaces.Unsigned_32;
      Priv_Key    : Crypto.KX.Secret_Key;
      Peer_Pub    : Crypto.KX.Public_Key;
      Key_Pair    : Crypto.KX.Key_Pair;
      Init_Status : Status;
   begin
      --  Load static private key from sdkconfig
      if WG_Keys.Get_Static_Private_Key (Priv_Key) = C_False then
         return C_False;
      end if;

      --  Derive our public key from the private key
      Crypto.KX.Derive_Public_Key (Key_Pair.Pub, Priv_Key, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;
      Key_Pair.Sec := Priv_Key;

      --  Initialize our identity
      Handshake.Initialize_Identity (My_Identity, Key_Pair, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;

      --  Load and configure each peer from sdkconfig.
      --  Peer 1 is required; peer 2+ are optional (skipped if no key).
      for P in Session.Peer_Index loop
         declare
            C_Peer : constant Interfaces.C.unsigned :=
              Interfaces.C.unsigned (P);
         begin
            if WG_Keys.Get_Peer_Public_Key (C_Peer, Peer_Pub) = C_True then
               Handshake.Initialize_Peer (My_Peers (P), Peer_Pub, Init_Status);
               if not Is_Success (Init_Status) then
                  --  Peer 1 failure is fatal; others are skipped
                  if P = 1 then
                     return C_False;
                  end if;
               else
                  Peer_Table.Set_Public_Key (P, Peer_Pub);

                  declare
                     AIPs : Peer_Table.Allowed_IP_Array :=
                       [others => (Addr => 0, Prefix_Len => 0)];
                     Addr : constant Interfaces.Unsigned_32 :=
                       Interfaces.Unsigned_32
                         (WG_Keys.Get_Peer_Allowed_IP (C_Peer));
                     Pfx  : constant Natural :=
                       Natural (WG_Keys.Get_Peer_Allowed_Prefix (C_Peer));
                  begin
                     AIPs (1) := (Addr => Addr, Prefix_Len => Pfx);
                     Peer_Table.Set_Allowed_IPs (P, AIPs, Count => 1);
                  end;

                  Session.Set_Persistent_Keepalive
                    (P,
                     Interval_S =>
                       Interfaces.Unsigned_64
                         (WG_Keys.Get_Peer_Keepalive (C_Peer)));
               end if;
            else
               --  Peer 1 must have a key configured
               if P = 1 then
                  return C_False;
               end if;
            end if;
         end;
      end loop;

      --  Packet pools are initialized from C (packet_pool_init) with
      --  statically-allocated semaphore handles before wg_init is called.

      --  Session table is initialized from C via wg_session_init()
      --  which creates the binary semaphore and calls Session.Init.
      --  That must be called before wg_init().

      Initialized := True;

      --  Mirror identity and peer configs into Protocol's SPARK-proven state.
      --  This bridge keeps both state copies in sync until Init itself
      --  moves to Protocol (Chunk 7).
      declare
         Peers : Wireguard.Protocol.Peer_Config_Array;
      begin
         for P in Session.Peer_Index loop
            Peers (P) := My_Peers (P);
         end loop;
         Wireguard.Protocol.Init_Protocol (My_Identity, Peers);
      end;

      return C_True;
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
   --  Mirrors Receive but for the wg_netif path:
   --    * Handshake messages are handled identically to Receive.
   --    * Transport data (type 4): decrypts in-place, then hands the RX
   --      pool buffer back to C via the return value.  Plaintext starts
   --      at offset Transport_Header_Size (16) inside the buffer.
   --      C receives PT_Len and uses buf->data + 16 directly.
   ---------------------------------------------------------------------------

   function Receive_Netif
     (RX_Buf   : System.Address;
      PT_Len   : access Unsigned_16;
      Peer_Out : access Interfaces.C.unsigned) return WG_Action
   is
      RX_Handle : Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      Peer_Idx  : Session.Peer_Index := 1;
   begin
      PT_Len.all := 0;
      Peer_Out.all := 0;

      if not Initialized then
         return Action_Error;
      end if;

      Messages.Acquire_RX_From_C (From_Address (RX_Buf), RX_Handle, RX_Length);

      if Messages.RX_Pool.Is_Null (RX_Handle) then
         return Action_Error;
      end if;

      if RX_Length = 0 then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         RX_Msg  : constant Messages.Undefined_Message :=
           Messages.Read_Undefined (RX_View);
         Result  : WG_Action;
      begin
         if not RX_Msg.Kind'Valid then
            Messages.RX_Pool.Free (RX_Handle);
            Result := Action_Error;
         else
            case RX_Msg.Kind is
               when Messages.Kind_Handshake_Initiation =>
                  Wireguard.Protocol.Handle_Initiation_RX
                    (RX_Handle, RX_Length, Peer_Idx, Result);

               when Messages.Kind_Handshake_Response   =>
                  Wireguard.Protocol.Handle_Response_RX
                    (RX_Handle, RX_Length, Peer_Idx, Result);

               when Messages.Kind_Transport_Data       =>
                  --  Minimum packet: header (16) + AEAD tag
                  if RX_Length < Unsigned_16 (Messages.Transport_Header_Size
                                              + Crypto.AEAD.Tag_Bytes)
                  then
                     Messages.RX_Pool.Free (RX_Handle);
                     Result := Action_Error;
                  else
                     declare
                        Pkt_PT_Len : Messages.Packet_Length;
                     begin
                        Wireguard.Protocol.Handle_Transport_RX
                          (RX_Handle, RX_Length,
                           Pkt_PT_Len, Peer_Idx, Result);
                        if Result = RX_Decryption_Success then
                           PT_Len.all := Unsigned_16 (Pkt_PT_Len);
                        end if;
                     end;
                  end if;

               when Messages.Kind_Cookie_Reply         =>
                  Messages.RX_Pool.Free (RX_Handle);
                  Result := Action_Error;
            end case;
         end if;

         Peer_Out.all := Interfaces.C.unsigned (Peer_Idx);
         return Result;
      end;
   end Receive_Netif;

end Wireguard;
