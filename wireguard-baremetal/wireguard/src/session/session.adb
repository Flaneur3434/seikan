--  Session - Implementation

with Crypto.KDF;
with Crypto.Helper;
with Utils.Result;

package body Session
  with
    SPARK_Mode    => On,
    Refined_State => (Peer_States => Peers, Mutex_State => Mtx)
is
   use Session_Keys;

   ---------------------------------------------------------------------------
   --  Internal Helpers
   ---------------------------------------------------------------------------

   --  Instantiate secure wipe for key and handshake types
   procedure Wipe_Keypair_Rec is new Crypto.Helper.Generic_Memzero (Keypair);

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref) is
   begin
      Threads.Mutex.Init_From_Handle (Mtx, Sem);
      Peers := (others => Null_Peer);
      Session_Keys.Init;
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
      Peers (Peer).Current := Peers (Peer).Next;
      Peers (Peer).Next := Null_Keypair;

      --  Update handshake timestamp
      Peers (Peer).Last_Handshake := Peers (Peer).Current.Created_At;

      --  Clear rekey state since we have a new session
      Peers (Peer).Rekey.Phase := Retry_Ready;
      Peers (Peer).Rekey.Start_At := Timer.Clock.Never;
      Peers (Peer).Rekey.Last_Sent := Timer.Clock.Never;
   end Activate_Next;

   ---------------------------------------------------------------------------
   --  Derive_And_Activate (atomic compound operation)
   ---------------------------------------------------------------------------

   function Mode_Of (P : Peer_Index) return Peer_Mode
   with Ghost, Global => (Input => Peers)
   is
   begin
      return Peers (P).Mode;
   end Mode_Of;

   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with Refined_Post => Mode_Of (Peer) = Established
   is
      Derive_Result : Keypair_Result.Result;
   begin
      Lock;

      Session_Keys.Derive_Keypair (HS, Now, Derive_Result);
      case Derive_Result.Kind is
         when Keypair_Result.Is_Ok  =>
            --  Place in the Next slot
            if Peers (Peer).Next.Valid then
               Wipe_Keypair_Rec (Peers (Peer).Next);
            end if;

            Peers (Peer).Next := Derive_Result.Ok;
            Peers (Peer).Active := True;

            Activate_Next (Peer);

         when Keypair_Result.Is_Err =>
            null;
      end case;

      Unlock;
   end Derive_And_Activate;

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

   procedure Mark_Received (Peer : Peer_Index; Now : Timer.Clock.Timestamp) is
   begin
      Lock;
      Peers (Peer).Last_Received := Now;
      Unlock;
   end Mark_Received;

   ---------------------------------------------------------------------------
   --  Counter management
   ---------------------------------------------------------------------------

   procedure Increment_Send_Counter
     (Peer : Peer_Index; Counter : out Unsigned_64) is
   begin
      Lock;
      Counter := Peers (Peer).Current.Send_Counter;
      Peers (Peer).Current.Send_Counter := Counter + 1;
      Unlock;
   end Increment_Send_Counter;

   ---------------------------------------------------------------------------
   --  Timer-driven session management
   ---------------------------------------------------------------------------

   procedure Expire_Session (Peer : Peer_Index)
   with
     Refined_Post =>
       Is_Mtx_Initialized
       and then not Threads.Mutex.Is_Locked (Mtx)
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
      Peers (Peer).Current := Null_Keypair;
      Peers (Peer).Previous := Null_Keypair;
      Peers (Peer).Next := Null_Keypair;

      --  Clear rekey state so the peer isn't stuck with
      --  Rekey_Attempted = True after expiry.
      Peers (Peer).Mode := Inactive;
      Peers (Peer).Rekey.Start_At := Timer.Clock.Never;
      Peers (Peer).Rekey.Last_Sent := Timer.Clock.Never;

      Unlock;
   end Expire_Session;

   procedure Set_Rekey_Flag (Peer : Peer_Index; Now : Timer.Clock.Timestamp) is
   begin
      Lock;

      --  Only set the attempt window start on the FIRST call.
      --  Retries must not reset the 90 s Rekey_Attempt_Time window.
      if Peers (Peer).Rekey.Phase = Retry_Ready then
         Peers (Peer).Mode := Rekeying;
         Peers (Peer).Rekey.Start_At := Now;
      end if;
      --  Always record when the last initiation was sent (retry gating).
      Peers (Peer).Rekey.Last_Sent := Now;

      Unlock;
   end Set_Rekey_Flag;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean) is
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
