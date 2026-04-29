--  Session - Implementation

with Replay;
with Crypto.Random;

package body Session
  with
    SPARK_Mode    => On,
    Refined_State => (Peer_States => Peers, Mutex_State => Mtx)
is
   use Session_Keys;
   use type Handshake.Handshake_Role;

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   procedure Init (Sem : not null Threads.Mutex.Semaphore_Ref)
   is
   begin
      Threads.Mutex.Init_From_Handle (Mtx, Sem);
      Peers := [others => <>];
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
      --  Rotate keys: Next → Current → Previous, clear Next.
      --  Order matters: save Current before overwriting.
      Peers (Peer).Previous        := Peers (Peer).Current;
      Peers (Peer).Current         := Peers (Peer).Next;
      Peers (Peer).Next            := (others => <>);
      Peers (Peer).Last_Handshake  := Peers (Peer).Current.Created_At;
      Peers (Peer).Last_Sent       := Peers (Peer).Current.Created_At;
      Peers (Peer).Last_Data_Sent  := Timer.Clock.Never;
      Peers (Peer).Last_Received   := Peers (Peer).Current.Created_At;
      Peers (Peer).Rekey_Start     := Timer.Clock.Never;
      Peers (Peer).Rekey_Last_Sent := Timer.Clock.Never;
      Peers (Peer).Active          := True;
      Peers (Peer).Mode            := Established;
   end Activate_Next;

   ---------------------------------------------------------------------------
   --  Derive_And_Activate (atomic compound operation)
   ---------------------------------------------------------------------------

   function Mode_Of (P : Peer_Index) return Peer_Mode
      is (Peers (P).Mode);

   procedure Derive_And_Activate
     (Peer   : Peer_Index;
      HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Status)
   with
     Refined_Post =>
       Session_Ready
       and then HS.Kind = Handshake.State_Empty
       and then (if Result = Success then Mode_Of (Peer) = Established)
   is
      --  Capture role BEFORE Derive_Keypair wipes the handshake state.
      --  Per WireGuard §5.4: only the initiator may do time-based
      --  rekeying, so we need to persist this in Peer_State.
      Initiator     : constant Boolean :=
        HS.Role = Handshake.Role_Initiator;
      Derive_Result : Keypair_Result.Result;
   begin
      Lock;

      Session_Keys.Derive_Keypair (HS, Now, Derive_Result);
      case Derive_Result.Kind is
         when Keypair_Result.Is_Ok  =>
            --  Place in the Next slot directly (overwrite, no wipe needed)
            Peers (Peer).Next := Derive_Result.Ok;
            Peers (Peer).Next.Valid := True;

            --  Activate_Next does the whole-record rotation
            --  including Mode := Established and rekey clearing
            Activate_Next (Peer);

            --  Record whether we were the initiator of this session.
            --  Must happen after Activate_Next (which sets Mode, etc).
            Peers (Peer).Is_Initiator := Initiator;
            Result := Success;

         when Keypair_Result.Is_Err =>
            Result := Error_Failed;
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
   --  Get_Previous
   ---------------------------------------------------------------------------

   procedure Get_Previous (Peer : Peer_Index; KP : out Keypair) is
   begin
      Lock;
      KP := Peers (Peer).Previous;
      Unlock;
   end Get_Previous;

   ---------------------------------------------------------------------------
   --  Timestamp updates
   ---------------------------------------------------------------------------

   procedure Mark_Sent (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Sent := Now;

      --  Sending any packet — keepalive or data — restarts the
      --  persistent-keepalive deadline.  Clear the transition flag
      --  so Tick does not re-fire keepalive until Refresh_Time_Flags
      --  re-arms it once the new deadline elapses.
      Peers (Peer).Persistent_Keepalive_Due := False;

      --  §6.4: reset attempt window on authenticated packet traversal.
      --  Extends the 90 s rekey-attempt window as long as there is
      --  actual traffic, preventing premature give-up.
      if Peers (Peer).Mode = Rekeying
        and then Now /= Timer.Clock.Never
      then
         Peers (Peer).Rekey_Start := Now;
      end if;

      Unlock;
   end Mark_Sent;

   procedure Mark_Data_Sent
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Data_Sent := Now;
      Unlock;
   end Mark_Data_Sent;

   procedure Mark_Received (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Peers (Peer).Last_Received := Now;

      --  §6.4: reset attempt window on authenticated packet traversal.
      if Peers (Peer).Mode = Rekeying
        and then Now /= Timer.Clock.Never
      then
         Peers (Peer).Rekey_Start := Now;
      end if;

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
   --  Timer-driven session management
   ---------------------------------------------------------------------------

   procedure Expire_Session (Peer : Peer_Index)
   with
     Refined_Post =>
       Session_Ready
       and then not Peers (Peer).Current.Valid
       and then not Peers (Peer).Previous.Valid
       and then not Peers (Peer).Next.Valid
   is
   begin
      Lock;

      declare
         Saved_PKA : constant Unsigned_64 :=
           Peers (Peer).Persistent_Keepalive_Ms;
         Saved_LH  : constant Timer.Clock.Timestamp :=
           Peers (Peer).Last_Handshake;
      begin
         Peers (Peer) := (others => <>);
         --  Preserve configuration that outlives sessions
         Peers (Peer).Persistent_Keepalive_Ms := Saved_PKA;
         --  Preserve Last_Handshake so the 540 s key-zeroing check
         --  in Tick can fire after the session has been expired.
         Peers (Peer).Last_Handshake := Saved_LH;
      end;

      Unlock;
   end Expire_Session;

   procedure Set_Rekey_Flag
     (Peer : Peer_Index; Now : Timer.Clock.Timestamp)
   is
      --  Generate 0..2000 ms of jitter from one random byte
      --  (per-second granularity is preserved; storage unit is ms).
      Rand_Buf : Byte_Array (0 .. 0);
      Jitter   : Unsigned_64;
   begin
      Crypto.Random.Fill_Random (Rand_Buf);
      Jitter := (Unsigned_64 (Rand_Buf (0)) mod 3) * 1_000;

      Lock;

      case Peers (Peer).Mode is
         when Established =>
            --  Transition Established → Rekeying.
            --  Valid_Peer(Established) guarantees Active and Current.Valid,
            --  which Valid_Peer(Rekeying) also requires.
            Peers (Peer).Mode            := Rekeying;
            Peers (Peer).Rekey_Start     := Now;
            Peers (Peer).Rekey_Last_Sent := Now;
            Peers (Peer).Rekey_Jitter_Ms := Jitter;

         when Rekeying =>
            --  Already rekeying — update retry timestamp and jitter.
            Peers (Peer).Rekey_Last_Sent := Now;
            Peers (Peer).Rekey_Jitter_Ms := Jitter;

         when Inactive =>
            --  No session to rekey — no-op.
            null;
      end case;

      Unlock;
   end Set_Rekey_Flag;

   ---------------------------------------------------------------------------
   --  Persistent keepalive configuration
   ---------------------------------------------------------------------------

   procedure Set_Persistent_Keepalive
     (Peer : Peer_Index; Interval_S : Unsigned_64)
   is
   begin
      Lock;
      --  Public API takes seconds (user-meaningful unit); store as
      --  milliseconds to match the internal time base.
      Peers (Peer).Persistent_Keepalive_Ms := Interval_S * 1_000;
      --  The deadline restarts from "now" whenever the interval
      --  changes (including disable).  Clear the transition flag
      --  so Tick does not fire a stale keepalive after a config
      --  change — Refresh_Time_Flags will re-set it once the new
      --  interval has actually elapsed since Last_Sent.
      Peers (Peer).Persistent_Keepalive_Due := False;
      Unlock;
   end Set_Persistent_Keepalive;

   ---------------------------------------------------------------------------
   --  Clear_Handshake_Timestamp
   ---------------------------------------------------------------------------

   procedure Clear_Handshake_Timestamp (Peer : Peer_Index)
   is
   begin
      Lock;
      Peers (Peer).Last_Handshake := Timer.Clock.Never;
      Unlock;
   end Clear_Handshake_Timestamp;

   ---------------------------------------------------------------------------
   --  Replay validation
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean)
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

   ---------------------------------------------------------------------------
   --  Replay validation (Previous keypair)
   ---------------------------------------------------------------------------

   procedure Validate_And_Update_Replay_Previous
     (Peer : Peer_Index; Counter : Unsigned_64; Accepted : out Boolean)
   is
   begin
      Lock;

      Replay.Validate_Counter
        (F        => Peers (Peer).Previous.Replay_Filter,
         Counter  => Counter,
         Limit    => Reject_After_Messages,
         Accepted => Accepted);

      Unlock;
   end Validate_And_Update_Replay_Previous;

end Session;
