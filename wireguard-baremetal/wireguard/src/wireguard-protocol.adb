--  Wireguard.Protocol - SPARK-Proven Protocol Core (Body)
--
--  Contains the protocol logic extracted from the C-facing Wireguard
--  package body.  SPARK_Mode => On enables formal verification of
--  buffer ownership, control flow, and state machine transitions.

with Interfaces;   use Interfaces;
with Utils;        use Utils;
with Handshake;
with Peer_Table;
with Session;
with Timer.Clock;
with Transport;
with WG_Types; use WG_Types;

package body Wireguard.Protocol
  with SPARK_Mode    => On,
       Refined_State => (Protocol_State => (My_Identity,
                                            My_Peers,
                                            HS_States,
                                            Last_Init_Peer,
                                            Last_Auto_Inits,
                                            Initialized))
is

   pragma Unevaluated_Use_Of_Old (Allow);

   use type Handshake.Handshake_Error;
   use type Handshake.Handshake_State_Kind;

   ---------------------------------------------------------------------------
   --  Protocol State
   ---------------------------------------------------------------------------

   My_Identity    : Handshake.Static_Identity;
   Initialized    : Boolean := False;

   My_Peers       : array (Session.Peer_Index) of Handshake.Peer_Config;
   HS_States      : array (Session.Peer_Index) of Handshake.Handshake_State :=
     [others => Handshake.Empty_Handshake];

   Last_Init_Peer  : Session.Peer_Index := 1;
   Last_Auto_Inits : array (Session.Peer_Index) of Timer.Clock.Timestamp :=
     [others => Timer.Clock.Never];

   ---------------------------------------------------------------------------
   --  Init_Protocol
   ---------------------------------------------------------------------------

   procedure Init_Protocol
     (Identity : Handshake.Static_Identity;
      Peers    : Peer_Config_Array)
   is
   begin
      My_Identity    := Identity;
      for P in Session.Peer_Index loop
         My_Peers (P) := Peers (P);
      end loop;
      HS_States       := [others => Handshake.Empty_Handshake];
      Last_Init_Peer  := 1;
      Last_Auto_Inits := [others => Timer.Clock.Never];
      Initialized     := True;
   end Init_Protocol;

   ---------------------------------------------------------------------------
   --  Handle_Initiation_RX
   ---------------------------------------------------------------------------

   procedure Handle_Initiation_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      Peer_Out  : out Session.Peer_Index;
      Action    : out WG_Action)
   is
      use Peer_Table.Lookup_Result;

      HS_Err  : Handshake.Handshake_Error;
      Temp_HS : Handshake.Handshake_State;
      Lookup  : Peer_Table.Lookup_Result.Result;
   begin
      Peer_Out := 1;  --  default
      Action := Action_Error;

      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Init_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return;
      end if;

      --  Copy message out of buffer, then process
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Msg     : constant Messages.Message_Handshake_Initiation :=
           Messages.Read_Initiation (RX_View);
      begin
         Handshake.Process_Initiation (Msg, Temp_HS, My_Identity, HS_Err);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      if HS_Err /= Handshake.HS_OK then
         return;
      end if;

      --  Identify which peer sent the initiation via their static key
      Lookup := Peer_Table.Lookup_By_Key (Temp_HS.Remote_Static);
      if Lookup.Kind /= Is_Ok then
         return;
      end if;

      --  Store handshake state in the correct per-peer slot
      declare
         P : constant Session.Peer_Index := Lookup.Ok;
      begin
         HS_States (P) := Temp_HS;
         Last_Init_Peer := P;
         Peer_Out := P;
      end;

      --  Tell C to call wg_create_response()
      Action := Action_Send_Response;
   end Handle_Initiation_RX;

   ---------------------------------------------------------------------------
   --  Handle_Response_RX
   ---------------------------------------------------------------------------

   procedure Handle_Response_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      Peer_Out  : out Session.Peer_Index;
      Action    : out WG_Action)
   with
     Refined_Post =>
       Messages.RX_Pool.Is_Null (RX_Handle)
       and then Messages.RX_Pool.Free_Count =
                  Messages.RX_Pool.Free_Count'Old + 1
       and then (if Action = Action_None
                 then Session.Is_Peer_Established (Peer_Out))
   is
      HS_Err      : Handshake.Handshake_Error;
      Sess_Status : Status;
      Found_Peer  : Session.Peer_Index := 1;
      Found       : Boolean := False;
      Msg         : Messages.Message_Handshake_Response;
   begin
      Peer_Out := 1;  --  default
      Action := Action_Error;

      --  Verify minimum length
      if RX_Length < Unsigned_16 (Messages.Handshake_Response_Size) then
         Messages.RX_Pool.Free (RX_Handle);
         return;
      end if;

      --  Read message from buffer
      declare
         RX_View : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
      begin
         Msg := Messages.Read_Response (RX_View);
      end;

      --  Done with RX buffer
      Messages.RX_Pool.Free (RX_Handle);

      --  Identify peer by receiver_index
      declare
         Recv_Idx : constant Unsigned_32 := Utils.To_U32 (Msg.Receiver);
      begin
         for P in Session.Peer_Index loop
            if HS_States (P).Kind = Handshake.State_Initiator_Sent
              and then HS_States (P).Local_Index = Recv_Idx
            then
               Found_Peer := P;
               Found := True;
               exit;
            end if;
         end loop;
      end;

      if not Found then
         return;
      end if;

      --  Process response using the matched peer's handshake state
      Handshake.Process_Response
        (Msg,
         HS_States (Found_Peer),
         My_Identity,
         My_Peers (Found_Peer),
         HS_Err);

      if HS_Err /= Handshake.HS_OK then
         return;
      end if;

      --  Initiator derives transport keys AND activates the new session
      --  atomically (single lock hold) after Process_Response.
      --  HS_States(P).Kind = State_Established at this point.
      declare
         Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      begin
         Session.Derive_And_Activate
           (Peer   => Found_Peer,
            HS     => HS_States (Found_Peer),
            Now    => Now,
            Result => Sess_Status);
      end;
      if not Is_Success (Sess_Status) then
         return;
      end if;

      Peer_Out := Found_Peer;
      Action := Action_None;
   end Handle_Response_RX;

   ---------------------------------------------------------------------------
   --  Create_Initiation
   ---------------------------------------------------------------------------

   procedure Create_Initiation
     (Peer    : Session.Peer_Index;
      TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   is
      Null_Ptr : Utils.C_Buffer_Ptr;  --  DIC: Is_Null holds
      Result   : Handshake.Initiation_Result;
      Handle   : Messages.Buffer_Handle;
      Ref      : Messages.Buffer_Ref;
   begin
      TX_Ptr  := Null_Ptr;
      TX_Len  := 0;
      Success := False;

      if not Initialized then
         return;
      end if;

      --  Allocate a TX pool buffer
      Messages.TX_Pool.Allocate (Handle);
      if Messages.TX_Pool.Is_Null (Handle) then
         return;
      end if;

      --  Build initiation message, then copy into TX buffer
      declare
         Msg : Messages.Message_Handshake_Initiation;
      begin
         Handshake.Create_Initiation
           (Msg, HS_States (Peer), My_Identity, My_Peers (Peer), Result);

         if not Result.Success then
            Messages.TX_Pool.Free (Handle);
            return;
         end if;

         Messages.TX_Pool.Borrow_Mut (Handle, Ref);
         Messages.Write_Initiation (Ref, Msg);
         Messages.TX_Pool.Return_Ref (Handle, Ref);
      end;

      --  Release to C layer for transmission
      pragma Warnings (Off, Handle);  --  nullified by Release_TX_To_C; dead after
      Messages.Release_TX_To_C
        (Handle, Messages.Packet_Length (Result.Length), TX_Ptr);

      TX_Len  := Messages.Packet_Length (Result.Length);
      Success := True;
   end Create_Initiation;

   ---------------------------------------------------------------------------
   --  Create_Response
   ---------------------------------------------------------------------------

   procedure Create_Response
     (TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   with
     Refined_Post =>
       (if Success
        then not Utils.Is_Null (TX_Ptr) and then TX_Len > 0
             and then Messages.TX_Pool.Free_Count =
                       Messages.TX_Pool.Free_Count'Old - 1
             and then Session.Is_Peer_Established (Last_Init_Peer)
        else Utils.Is_Null (TX_Ptr) and then TX_Len = 0
             and then Messages.TX_Pool.Free_Count =
                       Messages.TX_Pool.Free_Count'Old)
   is
      Null_Ptr    : Utils.C_Buffer_Ptr;  --  DIC: Is_Null holds
      P           : constant Session.Peer_Index := Last_Init_Peer;
      Resp_Result : Handshake.Response_Result;
      Handle      : Messages.Buffer_Handle;
      Sess_Status : Status;
   begin
      TX_Ptr  := Null_Ptr;
      TX_Len  := 0;
      Success := False;

      if not Initialized then
         return;
      end if;

      --  Allocate a TX pool buffer
      Messages.TX_Pool.Allocate (Handle);
      if Messages.TX_Pool.Is_Null (Handle) then
         return;
      end if;

      --  Build response message, then copy into TX buffer
      declare
         Resp : Messages.Message_Handshake_Response;
      begin
         Handshake.Create_Response
           (Resp, HS_States (P), My_Identity, Resp_Result);

         if not Resp_Result.Success then
            Messages.TX_Pool.Free (Handle);
            return;
         end if;

         declare
            Ref : Messages.Buffer_Ref;
         begin
            Messages.TX_Pool.Borrow_Mut (Handle, Ref);
            Messages.Write_Response (Ref, Resp);
            Messages.TX_Pool.Return_Ref (Handle, Ref);
         end;
      end;

      --  Responder derives transport keys AND activates the new session
      --  atomically (single lock hold) after Create_Response.
      --  Per WireGuard spec §5.4.4: responder has all Noise material.
      declare
         Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      begin
         Session.Derive_And_Activate
           (Peer   => P,
            HS     => HS_States (P),
            Now    => Now,
            Result => Sess_Status);
      end;

      if not Is_Success (Sess_Status) then
         Messages.TX_Pool.Free (Handle);
         return;
      end if;

      --  Release to C layer for transmission
      pragma Warnings (Off, Handle);  --  nullified by Release_TX_To_C; dead after
      Messages.Release_TX_To_C
        (Handle, Messages.Packet_Length (Resp_Result.Length), TX_Ptr);

      TX_Len  := Messages.Packet_Length (Resp_Result.Length);
      Success := True;
   end Create_Response;

   ---------------------------------------------------------------------------
   --  Auto_Handshake
   ---------------------------------------------------------------------------

   procedure Auto_Handshake
     (Peer   : Session.Peer_Index;
      TX_Ptr : out Utils.C_Buffer_Ptr;
      TX_Len : out Messages.Packet_Length)
   is
      Null_Ptr    : Utils.C_Buffer_Ptr;  --  DIC: Is_Null holds
      Now     : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      Success : Boolean;
   begin
      TX_Ptr  := Null_Ptr;
      TX_Len := 0;

      --  Handshake already in flight for this peer — don't re-initiate
      if HS_States (Peer).Kind /= Handshake.State_Empty then
         return;
      end if;

      --  Rate limit: at most once every Rekey_Timeout_S seconds per peer
      if Last_Auto_Inits (Peer) /= Timer.Clock.Never
        and then Now - Last_Auto_Inits (Peer) < Session.Rekey_Timeout_S
      then
         return;
      end if;

      Create_Initiation (Peer, TX_Ptr, TX_Len, Success);
      if Success then
         Last_Auto_Inits (Peer) := Now;
      end if;
   end Auto_Handshake;

   ---------------------------------------------------------------------------
   --  Build_And_Encrypt_TX
   ---------------------------------------------------------------------------

   procedure Build_And_Encrypt_TX
     (Peer    : Session.Peer_Index;
      Payload : Byte_Array;
      TX_Ptr  : out Utils.C_Buffer_Ptr;
      TX_Len  : out Messages.Packet_Length;
      Success : out Boolean)
   is
      Null_Ptr      : Utils.C_Buffer_Ptr;  --  DIC: Is_Null holds
      KP            : Session.Keypair;
      Send_Counter  : Unsigned_64;
      TX_Handle     : Messages.Buffer_Handle;
      Enc_Len       : Unsigned_16;
      Enc_Result    : Status;
   begin
      TX_Ptr  := Null_Ptr;
      TX_Len  := 0;
      Success := False;

      --  Get a nonce counter (atomically increments under lock)
      Session.Increment_Send_Counter (Peer, Send_Counter);

      --  Snapshot current keypair
      Session.Get_Current (Peer, KP);
      if not Session.Is_Valid (KP) then
         return;
      end if;

      --  Allocate TX pool buffer
      Messages.TX_Pool.Allocate (TX_Handle);
      if Messages.TX_Pool.Is_Null (TX_Handle) then
         return;
      end if;

      --  Encrypt payload into TX buffer (zero-length = keepalive)
      declare
         Ref : Messages.Buffer_Ref;
      begin
         Messages.TX_Pool.Borrow_Mut (TX_Handle, Ref);
         Transport.Encrypt_Into_Buffer
           (Ref            => Ref,
            Key            => Session.Send_Key (KP),
            Receiver_Index => Session.Receiver_Index (KP),
            Counter        => Send_Counter,
            Plaintext      => Payload,
            Length         => Enc_Len,
            Result         => Enc_Result);

         if not Is_Success (Enc_Result) then
            Messages.TX_Pool.Return_Ref (TX_Handle, Ref);
            Messages.TX_Pool.Free (TX_Handle);
            return;
         end if;

         Messages.TX_Pool.Return_Ref (TX_Handle, Ref);
      end;

      --  Record that we sent a packet (resets keepalive timer)
      declare
         Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      begin
         Session.Mark_Sent (Peer, Now);
      end;

      --  Release TX buffer to C for transmission
      pragma Warnings (Off, TX_Handle);  --  nullified by Release_TX_To_C; dead after
      Messages.Release_TX_To_C
        (TX_Handle, Messages.Packet_Length (Enc_Len), TX_Ptr);

      TX_Len  := Messages.Packet_Length (Enc_Len);
      Success := True;
   end Build_And_Encrypt_TX;

   ---------------------------------------------------------------------------
   --  Dispatch_Timer
   ---------------------------------------------------------------------------

   procedure Dispatch_Timer
     (Peer   : Session.Peer_Index;
      Action : Session.Timers.Timer_Action;
      TX_Ptr : out Utils.C_Buffer_Ptr;
      TX_Len : out Messages.Packet_Length)
   is
      use Session.Timers;
      Null_Ptr : Utils.C_Buffer_Ptr;  --  DIC: Is_Null holds
   begin
      TX_Ptr := Null_Ptr;
      TX_Len := 0;

      case Action is
         when No_Action =>
            null;

         when Send_Keepalive =>
            --  Encrypt empty payload → keepalive packet
            declare
               Empty   : constant Byte_Array (1 .. 0) := [others => 0];
               OK      : Boolean;
            begin
               Build_And_Encrypt_TX (Peer, Empty, TX_Ptr, TX_Len, OK);
               if not OK then
                  TX_Ptr := Null_Ptr;
                  TX_Len := 0;
               end if;
            end;

         when Session_Expired | Rekey_Timed_Out =>
            Session.Expire_Session (Peer);

         when Zero_All_Keys =>
            --  §6.3: 3×Reject_After_Time (540 s) — erase everything.
            Session.Expire_Session (Peer);
            Session.Clear_Handshake_Timestamp (Peer);
            Clear_HS_State (Peer);

         when Initiate_Rekey =>
            declare
               Success : Boolean;
            begin
               Create_Initiation (Peer, TX_Ptr, TX_Len, Success);
               if Success then
                  declare
                     Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
                  begin
                     if Now /= Timer.Clock.Never then
                        Session.Set_Rekey_Flag (Peer, Now);
                     end if;
                  end;
               end if;
            end;
      end case;
   end Dispatch_Timer;

   ---------------------------------------------------------------------------
   --  Clear_HS_State
   ---------------------------------------------------------------------------

   procedure Clear_HS_State (Peer : Session.Peer_Index) is
   begin
      HS_States (Peer) := Handshake.Empty_Handshake;
   end Clear_HS_State;

   ---------------------------------------------------------------------------
   --  Handle_Transport_RX
   ---------------------------------------------------------------------------

   procedure Handle_Transport_RX
     (RX_Handle : in out Messages.RX_Buffer_Handle;
      RX_Length : Messages.Packet_Length;
      PT_Len    : out Messages.Packet_Length;
      Peer_Out  : out Session.Peer_Index;
      Action    : out WG_Action)
   is
      use Peer_Table.Source_Result;

      Decrypt_Len    : Unsigned_16;
      Counter        : Unsigned_64;
      Decrypt_Result : Status;
      Replay_OK      : Boolean;

      KP            : Session.Keypair;
      Found_Peer    : Session.Peer_Index := 1;
      Found         : Boolean := False;
      Used_Previous : Boolean := False;
   begin
      PT_Len   := 0;
      Peer_Out := 1;
      Action   := Action_Error;

      --  Extract receiver_index from transport header (bytes 4-7, LE).
      --  Find which peer's Current or Previous keypair has matching
      --  Sender_Index.  Check Current first (common case), then Previous
      --  (in-flight packets during rekey transition).
      declare
         RX_View    : constant Messages.RX_Buffer_View :=
           Messages.RX_Pool.Borrow (RX_Handle);
         Recv_Bytes : constant Bytes_4 :=
           (RX_View.Buf_Ptr.Data (4),
            RX_View.Buf_Ptr.Data (5),
            RX_View.Buf_Ptr.Data (6),
            RX_View.Buf_Ptr.Data (7));
         Recv_Idx   : constant Unsigned_32 := To_U32 (Recv_Bytes);
      begin
         --  Pass 1: check Current keypair for each peer
         for P in Session.Peer_Index loop
            pragma Loop_Invariant (Session.Session_Ready);
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
               pragma Loop_Invariant (Session.Session_Ready);
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
         return;
      end if;

      Peer_Out := Found_Peer;

      --  Decrypt in-place in the RX pool buffer
      declare
         RX_Ref : Messages.RX_Buffer_Ref;
      begin
         Messages.RX_Pool.Borrow_Mut (RX_Handle, RX_Ref);
         Transport.Decrypt_In_Buffer
           (Ref       => RX_Ref,
            RX_Length => RX_Length,
            Key       => Session.Receive_Key (KP),
            Length    => Decrypt_Len,
            Counter   => Counter,
            Result    => Decrypt_Result);
         Messages.RX_Pool.Return_Ref (RX_Handle, RX_Ref);
      end;

      if not Is_Success (Decrypt_Result) then
         Messages.RX_Pool.Free (RX_Handle);
         return;
      end if;

      --  Validate replay counter against the correct keypair slot.
      --  Each keypair has its own counter space.
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

      if not Replay_OK then
         Messages.RX_Pool.Free (RX_Handle);
         return;
      end if;

      --  Authentic packet — mark received (resets keepalive timer)
      declare
         Now : constant Timer.Clock.Timestamp := Timer.Clock.Now;
      begin
         Session.Mark_Received (Found_Peer, Now);
      end;

      --  Zero-length plaintext = keepalive.  Authentic, already
      --  Mark_Received'd.  Free the buffer; C gets nothing.
      if Decrypt_Len = 0 then
         Messages.RX_Pool.Free (RX_Handle);
         Action := Action_None;
         return;
      end if;

      --  Cryptokey routing: verify inner source IP is in the
      --  sending peer's AllowedIPs.  Prevents a compromised peer
      --  from spoofing addresses outside its AllowedIPs (§4).
      --  IPv4 source address is at offset 12 in the IP header,
      --  which starts at Transport_Header_Size within the buffer.
      declare
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
            return;
         end if;
      end;

      --  Decryption succeeded with real payload.
      --  Leave the RX buffer alive — caller will Release_RX_To_C.
      PT_Len := Messages.Packet_Length (Decrypt_Len);
      Action := RX_Decryption_Success;
   end Handle_Transport_RX;

end Wireguard.Protocol;
