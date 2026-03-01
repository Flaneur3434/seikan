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
with Crypto.KX;
with Handshake;
with Messages;
with Transport;
with Session;
with Session.Timers;
with Timer.Clock;
with Peer_Table;
with WG_Keys;

package body Wireguard
  with SPARK_Mode => Off
is

   use type Handshake.Handshake_Error;

   --  C_bool helpers
   C_True  : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (1);
   C_False : constant Interfaces.C.C_bool := Interfaces.C.C_bool'Val (0);

   ---------------------------------------------------------------------------
   --  Package State
   ---------------------------------------------------------------------------

   My_Identity    : Handshake.Static_Identity;
   My_Peer        : Handshake.Peer_Config;
   HS_State       : Handshake.Handshake_State := Handshake.Empty_Handshake;
   Initialized    : Boolean := False;
   Last_Auto_Init : Timer.Clock.Timestamp := Timer.Clock.Never;

   --  Single peer — index 1 in the Session table.
   --  When multi-peer support is added, this will be derived from the
   --  receiver_index in the packet header.
   Peer_Idx : constant Session.Peer_Index := 1;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   function Init return C_bool is
      Priv_Key    : Crypto.KX.Secret_Key;
      Peer_Pub    : Crypto.KX.Public_Key;
      Key_Pair    : Crypto.KX.Key_Pair;
      Init_Status : Status;
   begin
      --  Load static private key from sdkconfig
      if WG_Keys.Get_Static_Private_Key (Priv_Key) = C_False then
         return C_False;
      end if;

      --  Load peer public key from sdkconfig
      if WG_Keys.Get_Peer_Public_Key (Peer_Pub) = C_False then
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

      --  Initialize peer configuration
      Handshake.Initialize_Peer (My_Peer, Peer_Pub, Init_Status);
      if not Is_Success (Init_Status) then
         return C_False;
      end if;

      --  Register the peer's public key in the peer table
      --  (cryptokey routing: maps key → peer index)
      Peer_Table.Set_Public_Key (Peer_Idx, Peer_Pub);

      --  Packet pools are initialized from C (packet_pool_init) with
      --  statically-allocated semaphore handles before wg_init is called.

      --  Reset protocol state
      HS_State := Handshake.Empty_Handshake;

      --  Session table is initialized from C via wg_session_init()
      --  which creates the binary semaphore and calls Session.Init.
      --  That must be called before wg_init().

      Initialized := True;

      return C_True;
   end Init;

   ---------------------------------------------------------------------------
   --  Helpers: Handshake sub-operations (body-local)
   ---------------------------------------------------------------------------

   --  Handle_Initiation_RX — Process initiation, signal C to build response
   --
   --  Just validates + processes the initiation message.  Does NOT allocate
   --  any TX buffer or build the response.  Returns Action_Send_Response
   --  so C can call wg_create_response() at its own pace.
   function Handle_Initiation_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length) return WG_Action
   is
      HS_Err : Handshake.Handshake_Error;
   begin
      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Init_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Process initiation directly from RX buffer (zero-copy)
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg     : constant Messages.Message_Handshake_Initiation
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Initiation (Msg, HS_State, My_Identity, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return Action_Error;
      end if;

      --  Tell C to call wg_create_response()
      return Action_Send_Response;
   end Handle_Initiation_RX;

   --  Handle_Response_RX — Initiator: process response, derive session
   function Handle_Response_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length) return WG_Action
   is
      HS_Err      : Handshake.Handshake_Error;
      Sess_Status : Status;
   begin
      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Response_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Process response directly from RX buffer (zero-copy)
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg     : Messages.Message_Handshake_Response
         with Import, Address => RX_View.Buf_Ptr.Data'Address;
      begin
         Handshake.Process_Response
           (Msg, HS_State, My_Identity, My_Peer, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return Action_Error;
      end if;

      --  Initiator derives transport keys AND activates the new session
      --  atomically (single lock hold) after Process_Response.
      --  HS_State.Kind = State_Established at this point.
      Session.Derive_And_Activate
        (Peer   => Peer_Idx,
         HS     => HS_State,
         Now    => Timer.Clock.Now,
         Result => Sess_Status);
      if not Is_Success (Sess_Status) then
         return Action_Error;
      end if;

      return Action_None;
   end Handle_Response_RX;

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
   begin
      TX_Addr := Null_Address;
      TX_Len  := 0;

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
         with Import, Address => TX_Ref.Buf_Ptr.Data'Address;
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

      TX_Ref.Buf_Ptr.Len := Enc_Len;
      Messages.TX_Pool.Return_Ref (TX_Handle, TX_Ref);

      --  Release TX buffer to C for transmission
      Messages.Release_TX_To_C
        (TX_Handle, Messages.Packet_Length (Enc_Len), TX_Addr);
      TX_Len := Enc_Len;
      return True;
   end Build_And_Encrypt_TX;

   ---------------------------------------------------------------------------
   --  Create_Initiation
   ---------------------------------------------------------------------------

   function Create_Initiation
     (Out_Len : access Unsigned_16) return System.Address
   is
      use System;

      Result : Handshake.Initiation_Result;
      Handle : Messages.Buffer_Handle;
      Ref    : Messages.Buffer_Ref;
      Addr   : System.Address;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Allocate a TX pool buffer
      Messages.TX_Pool.Allocate (Handle);
      if Messages.TX_Pool.Is_Null (Handle) then
         return Null_Address;
      end if;

      --  Build initiation directly in TX buffer (zero-copy)
      Messages.TX_Pool.Borrow_Mut (Handle, Ref);
      declare
         Msg : Messages.Message_Handshake_Initiation
         with Import, Address => Ref.Buf_Ptr.Data'Address;
      begin
         Handshake.Create_Initiation
           (Msg, HS_State, My_Identity, My_Peer, Result);
      end;

      if not Result.Success then
         Messages.TX_Pool.Return_Ref (Handle, Ref);
         Messages.TX_Pool.Free (Handle);
         return Null_Address;
      end if;

      Ref.Buf_Ptr.Len := Unsigned_16 (Result.Length);
      Messages.TX_Pool.Return_Ref (Handle, Ref);

      --  Release to C layer for transmission
      Messages.Release_TX_To_C
        (Handle, Messages.Packet_Length (Result.Length), Addr);

      Out_Len.all := Unsigned_16 (Result.Length);
      return Addr;
   end Create_Initiation;

   ---------------------------------------------------------------------------
   --  Create_Response
   ---------------------------------------------------------------------------

   function Create_Response
     (Out_Len : access Unsigned_16) return System.Address
   is
      use System;

      Resp_Result : Handshake.Response_Result;
      Handle      : Messages.Buffer_Handle;
      Ref         : Messages.Buffer_Ref;
      Sess_Status : Status;
      Addr        : System.Address;
   begin
      Out_Len.all := 0;

      if not Initialized then
         return Null_Address;
      end if;

      --  Allocate a TX pool buffer
      Messages.TX_Pool.Allocate (Handle);
      if Messages.TX_Pool.Is_Null (Handle) then
         return Null_Address;
      end if;

      --  Build response directly in TX buffer (zero-copy)
      Messages.TX_Pool.Borrow_Mut (Handle, Ref);
      declare
         Resp : Messages.Message_Handshake_Response
         with Import, Address => Ref.Buf_Ptr.Data'Address;
      begin
         Handshake.Create_Response (Resp, HS_State, My_Identity, Resp_Result);
      end;

      if not Resp_Result.Success then
         Messages.TX_Pool.Return_Ref (Handle, Ref);
         Messages.TX_Pool.Free (Handle);
         return Null_Address;
      end if;

      Ref.Buf_Ptr.Len := Unsigned_16 (Resp_Result.Length);
      Messages.TX_Pool.Return_Ref (Handle, Ref);

      --  Responder derives transport keys AND activates the new session
      --  atomically (single lock hold) after Create_Response.
      --  Per WireGuard spec §5.4.4: responder has all Noise material.
      Session.Derive_And_Activate
        (Peer   => Peer_Idx,
         HS     => HS_State,
         Now    => Timer.Clock.Now,
         Result => Sess_Status);
      if not Is_Success (Sess_Status) then
         Messages.TX_Pool.Free (Handle);
         return Null_Address;
      end if;

      --  Release to C layer for transmission
      Messages.Release_TX_To_C
        (Handle, Messages.Packet_Length (Resp_Result.Length), Addr);

      Out_Len.all := Unsigned_16 (Resp_Result.Length);
      return Addr;
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
      if Peer_ID not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
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
         end;
      end if;

      Out_Len.all := Len;
      return Addr;
   end Send;

   ---------------------------------------------------------------------------
   --  Auto_Handshake — Rate-limited handshake initiation for auto-init
   --
   --  Called by C when inner data is queued but no session exists.
   --  Ada rate-limits to at most once every Rekey_Timeout_S (5 s) and
   --  skips if a handshake is already in flight.
   --  Returns a TX buffer + length if C needs to sendto().
   --  TX_Buf = Null_Address means no packet to send (rate-limited or error).
   ---------------------------------------------------------------------------

   procedure Auto_Handshake
     (Peer   : Interfaces.C.unsigned;
      TX_Buf : out System.Address;
      TX_Len : out Interfaces.Unsigned_16)
   is
      use type Handshake.Handshake_State_Kind;

      Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      Len : aliased Unsigned_16 := 0;
   begin
      TX_Buf := System.Null_Address;
      TX_Len := 0;

      --  Validate peer index
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;

      --  Handshake already in flight — don't re-initiate
      if HS_State.Kind /= Handshake.State_Empty then
         return;
      end if;

      --  Rate limit: at most once every Rekey_Timeout_S seconds
      if Last_Auto_Init /= Timer.Clock.Never
        and then Now - Last_Auto_Init < Session.Rekey_Timeout_S
      then
         return;
      end if;

      TX_Buf := Create_Initiation (Len'Access);
      TX_Len := Len;
      Last_Auto_Init := Now;
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
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return;
      end if;
      P := Session.Peer_Index (Peer);

      --  Convert C uint8 → Ada Timer_Action enum
      if Action > Timer_Action'Pos (Timer_Action'Last) then
         return;
      end if;
      Ada_Action := Timer_Action'Val (Natural (Action));

      case Ada_Action is
         when No_Action =>
            null;

         when Session_Expired | Rekey_Timed_Out =>
            Session.Expire_Session (P);

         when Initiate_Rekey =>
            declare
               Len : aliased Unsigned_16 := 0;
            begin
               TX_Buf := Create_Initiation (Len'Access);
               TX_Len := Len;
               if TX_Buf /= System.Null_Address then
                  Session.Set_Rekey_Flag (P, Timer.Clock.Now);
               end if;
            end;

         when Send_Keepalive =>
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
      end case;
   end Dispatch_Timer;

   ---------------------------------------------------------------------------
   --  Handle_Transport_RX_Netif — Zero-copy variant of Handle_Transport_RX
   --
   --  Decrypts in-place in the RX pool buffer, then releases that buffer
   --  back to C rather than copying plaintext to a stack buffer.
   --  Plaintext sits at buf->data[Transport_Header_Size .. +len-1] when done.
   --  C takes ownership; it MUST eventually call rx_pool_free().
   ---------------------------------------------------------------------------

   function Handle_Transport_RX_Netif
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      PT_Len    : access Unsigned_16) return WG_Action
   is
      Header_Size : constant Natural := Messages.Transport_Header_Size;

      Decrypt_Len    : Unsigned_16;
      Counter        : Unsigned_64;
      Decrypt_Result : Status;
      Replay_OK      : Boolean;

      KP     : Session.Keypair;
      PT_Act : Natural := 0;
   begin
      PT_Len.all := 0;

      Session.Get_Current (Peer_Idx, KP);

      if not Session.Is_Valid (KP) then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      --  Decrypt in-place in the RX pool buffer
      declare
         RX_Ref : Messages.RX_Buffer_Ref;
      begin
         Messages.RX_Pool.Borrow_Mut (RX_Handle, RX_Ref);

         declare
            Pkt : Byte_Array (0 .. Natural (RX_Length) - 1)
            with Import, Address => RX_Ref.Buf_Ptr.Data'Address;
         begin
            Transport.Decrypt_Packet
              (Key     => Session.Receive_Key (KP),
               Packet  => Pkt,
               Length  => Decrypt_Len,
               Counter => Counter,
               Result  => Decrypt_Result);

            if Is_Success (Decrypt_Result) then
               Session.Validate_And_Update_Replay
                 (Peer     => Peer_Idx,
                  Counter  => Counter,
                  Accepted => Replay_OK);
               if Replay_OK then
                  Session.Mark_Received (Peer_Idx, Timer.Clock.Now);
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
     (RX_Buf : System.Address;
      PT_Len : access Unsigned_16) return WG_Action
   is
      RX_Handle : Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
   begin
      PT_Len.all := 0;

      if not Initialized then
         return Action_Error;
      end if;

      Messages.Acquire_RX_From_C (RX_Buf, RX_Handle, RX_Length);

      if Messages.RX_Pool.Is_Null (RX_Handle) then
         return Action_Error;
      end if;

      if RX_Length = 0 then
         Messages.RX_Pool.Free (RX_Handle);
         return Action_Error;
      end if;

      declare
         RX_View  : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg_Kind : constant Messages.Message_Kind :=
           Messages.Get_Message_Kind (RX_View.Buf_Ptr.Data (0));
      begin
         case Msg_Kind is
            when Messages.Kind_Handshake_Initiation =>
               return Handle_Initiation_RX (RX_Handle, RX_Length);

            when Messages.Kind_Handshake_Response =>
               return Handle_Response_RX (RX_Handle, RX_Length);

            when Messages.Kind_Transport_Data =>
               return Handle_Transport_RX_Netif (RX_Handle, RX_Length, PT_Len);

            when Messages.Kind_Cookie_Reply | Messages.Kind_Unknown =>
               Messages.RX_Pool.Free (RX_Handle);
               return Action_Error;
         end case;
      end;
   end Receive_Netif;

end Wireguard;
