--  Session - Implementation

with Crypto.KDF;
with Crypto.Helper;

package body Session
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Internal Helpers
   ---------------------------------------------------------------------------

   --  Instantiate secure wipe for key and handshake types
   procedure Wipe_Keypair_Rec is new
     Crypto.Helper.Generic_Memzero (Keypair);

   procedure Wipe_HS_State is new
     Crypto.Helper.Generic_Memzero (Handshake.Handshake_State);

   --  Wipe all handshake ephemeral material and reset to State_Empty.
   --  Wraps Generic_Memzero with a postcondition SPARK can verify.
   --  After memzero the Kind field is bit-zero (= State_Empty as the
   --  first enum literal), but the prover can't see through memzero's
   --  untyped wipe, so we set Kind explicitly.
   procedure Wipe_Handshake (HS : in out Handshake.Handshake_State)
   with Post => HS.Kind = Handshake.State_Empty
   is
   begin
      Wipe_HS_State (HS);
      HS.Kind := Handshake.State_Empty;
   end Wipe_Handshake;

   --  Empty input for KDF2(C, "") derivation
   Empty_Input : constant Byte_Array (1 .. 0) := (others => 0);

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref) is
   begin
      Threads.Mutex.Init_From_Handle (Mtx, Sem);
      Peers := (others => Null_Peer);
      Next_KP_ID := 1;
   end Init;

   ---------------------------------------------------------------------------
   --  Lock / Unlock
   ---------------------------------------------------------------------------

   procedure Lock is
   begin
      Threads.Mutex.Lock (Mtx);
   end Lock;

   procedure Unlock is
   begin
      Threads.Mutex.Unlock (Mtx);
   end Unlock;

   ---------------------------------------------------------------------------
   --  Derive_Keypair
   ---------------------------------------------------------------------------

   procedure Derive_Keypair
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   is
      Key1 : Crypto.KDF.KDF_Key;
      Key2 : Crypto.KDF.KDF_Key;
      KP   : Keypair;
   begin
      --  Derive two keys: KDF2(Chaining_Key, "")
      --    Key1 = τ1 (initiator's send key)
      --    Key2 = τ2 (initiator's receive key)
      Crypto.KDF.KDF2
        (Key     => HS.Chaining,
         Input   => Empty_Input,
         Output1 => Key1,
         Output2 => Key2,
         Result  => Result);

      if Result /= Success then
         Wipe_Handshake (HS);
         return;
      end if;

      --  Build keypair based on role
      case HS.Role is
         when Handshake.Role_Initiator =>
            KP.Send_Key    := Key1;
            KP.Receive_Key := Key2;
         when Handshake.Role_Responder =>
            KP.Send_Key    := Key2;
            KP.Receive_Key := Key1;
      end case;

      KP.Sender_Index   := Unsigned_32 (HS.Local_Index);
      KP.Receiver_Index := Unsigned_32 (HS.Remote_Index);
      KP.Send_Counter   := 0;
      Replay.Reset (KP.Replay_Filter);
      KP.Created_At     := Now;
      KP.ID             := Next_KP_ID;
      KP.Valid          := True;
      Next_KP_ID        := Next_KP_ID + 1;

      --  Place in the Next slot
      if Peers (Peer).Next.Valid then
         Wipe_Keypair_Rec (Peers (Peer).Next);
      end if;
      Peers (Peer).Next := KP;
      Peers (Peer).Active := True;

      --  Forward secrecy: wipe all ephemeral handshake material
      Wipe_Handshake (HS);
   end Derive_Keypair;

   ---------------------------------------------------------------------------
   --  Activate_Next
   ---------------------------------------------------------------------------

   procedure Activate_Next (Peer : Peer_Index) is
   begin
      if not Peers (Peer).Next.Valid then
         return;
      end if;

      --  Wipe the old Previous keypair
      if Peers (Peer).Previous.Valid then
         Wipe_Keypair_Rec (Peers (Peer).Previous);
      end if;

      --  Rotate: Previous ← Current, Current ← Next, Next ← null
      Peers (Peer).Previous := Peers (Peer).Current;
      Peers (Peer).Current  := Peers (Peer).Next;
      Peers (Peer).Next     := Null_Keypair;

      --  Update handshake timestamp
      Peers (Peer).Last_Handshake := Peers (Peer).Current.Created_At;

      --  Clear rekey state since we have a new session
      Peers (Peer).Rekey_Attempted    := False;
      Peers (Peer).Rekey_Attempt_Start := Timer.Clock.Never;
   end Activate_Next;

   ---------------------------------------------------------------------------
   --  Derive_And_Activate (atomic compound operation)
   ---------------------------------------------------------------------------

   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   is
   begin
      Lock;
      Derive_Keypair (Peer, HS, Now, Result);
      if Result = Success then
         Activate_Next (Peer);
      end if;
      Unlock;
   end Derive_And_Activate;

   ---------------------------------------------------------------------------
   --  Keypair Accessors
   ---------------------------------------------------------------------------

   function Is_Valid (KP : Keypair) return Boolean is
   begin
      return KP.Valid;
   end Is_Valid;

   function Send_Key (KP : Keypair) return Session_Key is
   begin
      return KP.Send_Key;
   end Send_Key;

   function Receive_Key (KP : Keypair) return Session_Key is
   begin
      return KP.Receive_Key;
   end Receive_Key;

   function Receiver_Index (KP : Keypair) return Unsigned_32 is
   begin
      return KP.Receiver_Index;
   end Receiver_Index;

   ---------------------------------------------------------------------------
   --  Get_Current
   ---------------------------------------------------------------------------

   procedure Get_Current (Peer : Peer_Index; KP : out Keypair) is
   begin
      Lock;
      KP := Peers (Peer).Current;
      Unlock;
   end Get_Current;

   ---------------------------------------------------------------------------
   --  Timestamp updates
   ---------------------------------------------------------------------------

   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp) is
   begin
      Lock;
      Peers (Peer).Last_Sent := Now;
      Unlock;
   end Mark_Sent;

   procedure Mark_Received
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Received := Now;
      Unlock;
   end Mark_Received;

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64)
   is
   begin
      Lock;
      Counter := Peers (Peer).Current.Send_Counter;
      Peers (Peer).Current.Send_Counter := Counter + 1;
      Unlock;
   end Increment_Send_Counter;

   ---------------------------------------------------------------------------
   --  Session invalidation
   ---------------------------------------------------------------------------

   procedure Expire_Session (Peer : Peer_Index)
   with Pre  => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx),
        Post => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx)
                and then not Peers (Peer).Current.Valid
                and then not Peers (Peer).Previous.Valid
                and then not Peers (Peer).Next.Valid
   is
   begin
      Lock;
      if Peers (Peer).Current.Valid then
         Wipe_Keypair_Rec (Peers (Peer).Current);
      end if;
      if Peers (Peer).Previous.Valid then
         Wipe_Keypair_Rec (Peers (Peer).Previous);
      end if;
      if Peers (Peer).Next.Valid then
         Wipe_Keypair_Rec (Peers (Peer).Next);
      end if;
      Peers (Peer).Current  := Null_Keypair;
      Peers (Peer).Previous := Null_Keypair;
      Peers (Peer).Next     := Null_Keypair;
      Unlock;
   end Expire_Session;

   procedure Clear_Rekey_Flag (Peer : Peer_Index)
   with Pre  => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx),
        Post => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx)
   is
   begin
      Lock;
      Peers (Peer).Rekey_Attempted     := False;
      Peers (Peer).Rekey_Attempt_Start := Timer.Clock.Never;
      Unlock;
   end Clear_Rekey_Flag;

   procedure Set_Rekey_Flag
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   with Pre  => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx),
        Post => Is_Mtx_Initialized and then not Threads.Mutex.Is_Locked (Mtx)
   is
   begin
      Lock;
      Peers (Peer).Rekey_Attempted     := True;
      Peers (Peer).Rekey_Attempt_Start := Now;
      Unlock;
   end Set_Rekey_Flag;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay
     (Peer     : Peer_Index;
      Counter  : Unsigned_64;
      Accepted : out Boolean)
   is
   begin
      Lock;
      Replay.Validate_Counter
        (F        => Peers (Peer).Current.Replay_Filter,
         Counter  => Counter,
         Limit    => Reject_After_Messages,
         Accepted => Accepted);
      Unlock;
   end Validate_And_Update_Replay;

end Session;
