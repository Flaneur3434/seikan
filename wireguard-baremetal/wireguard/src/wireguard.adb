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
with Crypto.KX;
with Handshake;
with Messages;
with Transport;
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
   --  Helpers: Handshake sub-operations (body-local)
   ---------------------------------------------------------------------------

   ---------------------------------------------------------------------------
   --  Build_And_Encrypt_TX — Internal TX path
   --
   --  Allocates a TX pool buffer, encrypts the given plaintext (which
   --  may be zero-length for a keepalive), and releases the buffer to
   --  C for transmission.
   --
   --  On success: TX_Addr = pool buffer address, TX_Len = wire bytes.
   --  On failure: TX_Addr = Null_Address, TX_Len = 0.
   ---------------------------------------------------------------------------

   function Build_And_Encrypt_TX
     (Peer    : Session.Peer_Index;
      Payload : Byte_Array;
      TX_Addr : out System.Address;
      TX_Len  : out Unsigned_16) return Boolean
   is
      use System;

      KP           : Session.Keypair;
      Send_Counter : Unsigned_64;
      TX_Handle    : Messages.Buffer_Handle;
      TX_Ref       : Messages.Buffer_Ref;
      Enc_Len      : Unsigned_16;
      Enc_Result   : Status;
      Ptr          : C_Buffer_Ptr;
   begin
      TX_Addr := Null_Address;
      TX_Len := 0;

      --  Get a nonce counter (atomically increments under lock)
      Session.Increment_Send_Counter (Peer, Send_Counter);

      --  Snapshot current keypair
      Session.Get_Current (Peer, KP);
      if not Session.Is_Valid (KP) then
         return False;
      end if;

      --  Allocate TX pool buffer
      Messages.TX_Pool.Allocate (TX_Handle);
      if Messages.TX_Pool.Is_Null (TX_Handle) then
         return False;
      end if;

      --  Encrypt payload into TX buffer (zero-length = keepalive)
      Messages.TX_Pool.Borrow_Mut (TX_Handle, TX_Ref);
      declare
         Out_Pkt : Byte_Array (0 .. Messages.Packet_Size - 1)
         with Import, Address => Messages.TX_Pool.Get_Ptr (TX_Ref).Data'Address;
      begin
         Transport.Encrypt_Packet
           (Key            => Session.Send_Key (KP),
            Receiver_Index => Session.Receiver_Index (KP),
            Counter        => Send_Counter,
            Plaintext      => Payload,
            Packet         => Out_Pkt,
            Length         => Enc_Len,
            Result         => Enc_Result);
      end;

      if not Is_Success (Enc_Result) then
         Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);
         Messages.TX_Pool.Free (TX_Handle);
         return False;
      end if;

      --  Record that we sent a packet (resets keepalive timer)
      Session.Mark_Sent (Peer, Timer.Clock.Now);

      Messages.TX_Pool.Get_Ptr (TX_Ref).Len := Enc_Len;
      Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);

      --  Release TX buffer to C for transmission
      Messages.Release_TX_To_C
        (TX_Handle, Messages.Packet_Length (Enc_Len), Ptr);
      TX_Addr := To_Address (Ptr);
      TX_Len := Enc_Len;
      return True;
   end Build_And_Encrypt_TX;

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

      Peer : Session.Peer_Index;
      Addr : System.Address;
      Len  : Unsigned_16;
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
            if not Build_And_Encrypt_TX (Peer, Empty, Addr, Len) then
               return Null_Address;
            end if;
         end;
      else
         declare
            Data : Byte_Array (0 .. Natural (Payload_Len) - 1)
            with Import, Address => Payload;
         begin
            if not Build_And_Encrypt_TX (Peer, Data, Addr, Len) then
               return Null_Address;
            end if;
            --  Track data-send timestamp (distinct from keepalive)
            --  for unresponsive peer detection (§6.5).
            Session.Mark_Data_Sent (Peer, Timer.Clock.Now);
         end;
      end if;

      Out_Len.all := Len;
      return Addr;
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

      if Ada_Action = Send_Keepalive then
         --  Keepalive needs Build_And_Encrypt_TX (Transport layer,
         --  SPARK_Mode => Off) — handle locally until chunk 5.
         declare
            Empty : constant Byte_Array (1 .. 0) := [others => 0];
            OK    : Boolean;
         begin
            OK := Build_And_Encrypt_TX (P, Empty, TX_Buf, TX_Len);
            if not OK then
               TX_Buf := System.Null_Address;
               TX_Len := 0;
            end if;
         end;
      else
         --  All other timer actions delegate to Protocol
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
      end if;
   end Dispatch_Timer;

   ---------------------------------------------------------------------------
   --  Handle_Transport_RX_Netif — Zero-copy variant of Handle_Transport_RX
   --
   --  Identifies the peer from the Transport header's receiver_index
   --  (bytes 4-7), matching against each peer's Current keypair's
   --  Sender_Index.  Decrypts in-place, validates replay, and hands
   --  the buffer back to C.
   ---------------------------------------------------------------------------

   function Handle_Transport_RX_Netif
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      PT_Len    : access Unsigned_16;
      Peer_Out  : out Session.Peer_Index) return WG_Action
   is
      Decrypt_Len    : Unsigned_16;
      Counter        : Unsigned_64;
      Decrypt_Result : Status;
      Replay_OK      : Boolean;

      KP            : Session.Keypair;
      PT_Act        : Natural := 0;
      Found_Peer    : Session.Peer_Index := 1;
      Found         : Boolean := False;
      Used_Previous : Boolean := False;
   begin
      PT_Len.all := 0;
      Peer_Out := 1;

      --  Extract receiver_index from transport header (bytes 4-7, LE).
      --  Find which peer's Current or Previous keypair has matching
      --  Sender_Index.  Check Current first (common case), then Previous
      --  (in-flight packets during rekey transition).
      declare
         RX_View    : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Recv_Bytes : constant Utils.Bytes_4 :=
           (RX_View.Buf_Ptr.Data (4),
            RX_View.Buf_Ptr.Data (5),
            RX_View.Buf_Ptr.Data (6),
            RX_View.Buf_Ptr.Data (7));
         Recv_Idx   : constant Unsigned_32 := Utils.To_U32 (Recv_Bytes);
      begin
         --  Pass 1: check Current keypair for each peer
         for P in Session.Peer_Index loop
            declare
               Peer_KP : Session.Keypair;
            begin
               Session.Get_Current (P, Peer_KP);
               if Session.Is_Valid (Peer_KP)
                 and then Peer_KP.Sender_Index = Recv_Idx
               then
                  Found_Peer := P;
                  Found := True;
                  KP := Peer_KP;
                  exit;
               end if;
            end;
         end loop;

         --  Pass 2: check Previous keypair (fallback for rekey transition)
         if not Found then
            for P in Session.Peer_Index loop
               declare
                  Prev_KP : Session.Keypair;
               begin
                  Session.Get_Previous (P, Prev_KP);
                  if Session.Is_Valid (Prev_KP)
                    and then Prev_KP.Sender_Index = Recv_Idx
                  then
                     Found_Peer := P;
                     Found := True;
                     Used_Previous := True;
                     KP := Prev_KP;
                     exit;
                  end if;
               end;
            end loop;
         end if;
      end;

      if not Found then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      Peer_Out := Found_Peer;

      --  Decrypt in-place in the RX pool buffer
      declare
         RX_Ref : Messages.RX_Buffer_Ref;
      begin
         Messages.RX_Pool.Borrow_Mut (RX_Handle, RX_Ref);

         declare
            Pkt : Byte_Array (0 .. Natural (RX_Length) - 1)
            with Import, Address => Messages.RX_Pool.Get_Ptr (RX_Ref).Data'Address;
         begin
            Transport.Decrypt_Packet
              (Key     => Session.Receive_Key (KP),
               Packet  => Pkt,
               Length  => Decrypt_Len,
               Counter => Counter,
               Result  => Decrypt_Result);

            if Is_Success (Decrypt_Result) then
               --  Use the correct replay filter for the slot that matched.
               --  Each keypair has its own counter space: Current and Previous
               --  slots are independent, so a counter valid in one may not
               --  be valid in the other.
               if Used_Previous then
                  Session.Validate_And_Update_Replay_Previous
                    (Peer     => Found_Peer,
                     Counter  => Counter,
                     Accepted => Replay_OK);
               else
                  Session.Validate_And_Update_Replay
                    (Peer     => Found_Peer,
                     Counter  => Counter,
                     Accepted => Replay_OK);
               end if;
               if Replay_OK then
                  Session.Mark_Received (Found_Peer, Timer.Clock.Now);
               end if;
               if not Replay_OK then
                  Decrypt_Result := Error_Failed;
               end if;
            end if;

            if Is_Success (Decrypt_Result) then
               PT_Act := Natural (Decrypt_Len);
            end if;
         end;

         Messages.RX_Pool.Return_Ref (RX_Handle, RX_Ref);
      end;

      if not Is_Success (Decrypt_Result) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Zero-length plaintext = keepalive.  Authentic, already
      --  Mark_Received'd.  Free the buffer here; C gets nothing.
      if PT_Act = 0 then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_None;
      end if;

      --  Cryptokey routing: verify inner source IP is in the
      --  sending peer's AllowedIPs.  Prevents a compromised peer
      --  from spoofing addresses outside its AllowedIPs (§4).
      --  IPv4 source address is at offset 12 in the IP header,
      --  which starts at Transport_Header_Size within the buffer.
      declare
         use Peer_Table.Source_Result;

         RX_View   : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Hdr_Off   : constant Natural := Messages.Transport_Header_Size;
         Src_Bytes : constant Bytes_4 :=
           (RX_View.Buf_Ptr.Data (Hdr_Off + 12),
            RX_View.Buf_Ptr.Data (Hdr_Off + 13),
            RX_View.Buf_Ptr.Data (Hdr_Off + 14),
            RX_View.Buf_Ptr.Data (Hdr_Off + 15));
         Src_IP    : constant Unsigned_32 := To_U32 (Src_Bytes);
         Check     : constant Peer_Table.Source_Result.Result :=
           Peer_Table.Check_Source (Found_Peer, Src_IP);
      begin
         if Check.Kind /= Is_Ok then
            Messages.RX_Pool.Free (RX_Handle);
            return Action_Error;
         end if;
      end;

      --  Decryption succeeded with real payload.
      --  Release the pool buffer to C.  C is now responsible for
      --  calling rx_pool_free() (either directly or via pbuf_custom).
      --  We do NOT call RX_Pool.Free here.
      PT_Len.all := Unsigned_16 (PT_Act);

      --  Return the physical RX buffer handle to C.
      --  We deliberately leave RX_Handle as non-null so the address
      --  survives; Receive_Netif will read it back via Release_RX_To_C.
      return RX_Decryption_Success;
   end Handle_Transport_RX_Netif;

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
                  Result :=
                    Handle_Transport_RX_Netif
                      (RX_Handle, RX_Length, PT_Len, Peer_Idx);

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
