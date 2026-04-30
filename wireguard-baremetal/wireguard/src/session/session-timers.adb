--  Session.Timers — Implementation

package body Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Refresh_Time_Flags — Recompute time-based transition flags
   --
   --  Single owner of all Now-based comparisons for Tick.  Called at
   --  the entry of Tick_All and On_Peer_Timer_Due so the flags are
   --  always live when Tick runs.  Each call fully recomputes (set
   --  or clear); transitions therefore do not need to eagerly clear
   --  the flags.
   --
   --  After step 7c, this routine performs no elapsed-time
   --  arithmetic.  Every one of the eight rules is a uniform
   --  "deadline armed AND now past it" test against a deadline that
   --  some prior transition (chunk 7b) stamped in Peer_State.  All
   --  context-sensitive arming logic — "only initiator", "only in
   --  Rekeying", "only when Last_Data_Sent > Last_Received", etc. —
   --  lives at the transition site; the deadline being /= Never
   --  encodes "rule currently armed".
   ---------------------------------------------------------------------------

   procedure Refresh_Time_Flags
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp)
   is
      Peer : Peer_State renames Peers (Peer_Idx);
   begin
      Peer.Persistent_Keepalive_Due :=
        Peer.Persistent_Keepalive_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Persistent_Keepalive_Deadline;

      Peer.Reactive_Keepalive_Due :=
        Peer.Reactive_Keepalive_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Reactive_Keepalive_Deadline;

      Peer.Unresponsive_Peer_Due :=
        Peer.Unresponsive_Peer_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Unresponsive_Peer_Deadline;

      Peer.Zero_Keys_Due :=
        Peer.Zero_Keys_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Zero_Keys_Deadline;

      Peer.Session_Expire_Time_Due :=
        Peer.Session_Expire_Time_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Session_Expire_Time_Deadline;

      Peer.Rekey_Time_Due :=
        Peer.Rekey_Time_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Rekey_Time_Deadline;

      Peer.Rekey_Timed_Out_Due :=
        Peer.Rekey_Timed_Out_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Rekey_Timed_Out_Deadline;

      Peer.Rekey_Retry_Due :=
        Peer.Rekey_Retry_Deadline /= Timer.Clock.Never
        and then Now >= Peer.Rekey_Retry_Deadline;
   end Refresh_Time_Flags;

   ---------------------------------------------------------------------------
   --  Tick — Evaluate one peer, return what C should do
   --
   --  Priority is implicit in evaluation order (first match wins):
   --    0. Key zeroing      (540 s — erase stale inactive peers)
   --    1. Session expired   (hard deadline — drop everything)
   --    2. Rekey timed out   (give up trying)
   --    3. Initiate rekey    (time/counter/unresponsive triggers)
   --    4. Send keepalive    (idle peer needs a ping)
   --    5. No action
   ---------------------------------------------------------------------------

   function Tick
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp) return Timer_Action
   with
     Refined_Post =>
       -- Zero-keys is the only action that can fire on an inactive
       -- or invalid-keypair peer (it intentionally runs first, before
       -- the Active/Valid gate).  Every other action is gated by it.
       (if not Peers (Peer_Idx).Active
          or else not Peers (Peer_Idx).Current.Valid
        then
          Tick'Result in Zero_All_Keys | No_Action)
       -- Zero_All_Keys is only emitted when its flag is set.
       and then
         (if Tick'Result = Zero_All_Keys
          then Peers (Peer_Idx).Zero_Keys_Due)
       -- Priority: expired dominates everything
       and then
         (if Tick'Result = Session_Expired
          then
            Peers (Peer_Idx).Session_Expire_Time_Due
            or else
              Peers (Peer_Idx).Current.Send_Counter >= Reject_After_Messages)
       -- Rekey_Timed_Out only fires from Rekeying mode and only when
       -- its flag is set.
       and then
         (if Tick'Result = Rekey_Timed_Out
          then
            Peers (Peer_Idx).Mode = Rekeying
            and then Peers (Peer_Idx).Rekey_Timed_Out_Due)
       -- Priority: timed_out dominates rekey
       and then
         (if Tick'Result = Initiate_Rekey
            and then Peers (Peer_Idx).Mode = Rekeying
          then
            not Peers (Peer_Idx).Rekey_Timed_Out_Due)
       -- Established rekey: initiator-only for time, any peer for
       -- counter or unresponsive peer detection
       and then
         (if Tick'Result = Initiate_Rekey
            and then Peers (Peer_Idx).Mode = Established
          then
            Peers (Peer_Idx).Is_Initiator
            or else
              Peers (Peer_Idx).Current.Send_Counter >= Rekey_After_Messages
            or else
              Peers (Peer_Idx).Unresponsive_Peer_Due
            or else
              Peers (Peer_Idx).Rekey_Time_Due)
       -- Send_Keepalive only fires when one of the two keepalive flags
       -- is set (priority: reactive over persistent, but either implies
       -- the action).
       and then
         (if Tick'Result = Send_Keepalive
          then
            Peers (Peer_Idx).Reactive_Keepalive_Due
            or else Peers (Peer_Idx).Persistent_Keepalive_Due)
   is
      Peer : constant Peer_State := Peers (Peer_Idx);
   begin
      --  0. Key zeroing at 3×Reject (540 s) — §6.3 last sentence.
      --  Step 6b.4: read transition flag.
      if Peer.Zero_Keys_Due then
         return Zero_All_Keys;
      end if;

      --  Inactive/invalid peers need nothing (below 540 s threshold)
      if not Peer.Active or else not Peer.Current.Valid then
         return No_Action;
      end if;

      --  1. Hard expiry — reject-after limits.
      --  Counter limit stays inline (counter, not time); time limit
      --  is now a transition flag.
      if Peer.Session_Expire_Time_Due
        or else Peer.Current.Send_Counter >= Reject_After_Messages
      then
         return Session_Expired;
      end if;

      case Peer.Mode is
         when Established =>
            --  Counter-based rekey: ANY peer (§6.2 paragraph 1).
            --  Counter is not time, so it stays inline.
            if Peer.Current.Send_Counter >= Rekey_After_Messages then
               return Initiate_Rekey;
            end if;

            --  Time-based rekey: ONLY initiator (§6.2 paragraph 2).
            --  Step 6b.4: read transition flag.
            if Peer.Rekey_Time_Due then
               return Initiate_Rekey;
            end if;

            --  Unresponsive peer detection — §6.5 last paragraph
            --  Matches wireguard-go expiredNewHandshake (15 s).
            --  Step 6b.3: read the transition flag set by
            --  Refresh_Time_Flags from Last_Data_Sent / Last_Received.
            if Peer.Unresponsive_Peer_Due then
               return Initiate_Rekey;
            end if;

         when Rekeying    =>
            --  Rekey attempt timed out (90 s window exhausted).
            --  Must be checked BEFORE retry gating so we don't
            --  keep retrying after the attempt window is exhausted.
            --  Step 6b.4: read transition flag.
            if Peer.Rekey_Timed_Out_Due then
               return Rekey_Timed_Out;
            end if;

            --  Retry gating: re-send initiation every 5 + jitter s.
            --  Step 6b.4: read transition flag.
            if Peer.Rekey_Retry_Due then
               return Initiate_Rekey;
            end if;

         when Inactive    =>
            null;
      end case;

      --  4. Reactive keepalive — received recently, haven't sent back.
      --  Step 6b.2: read the transition flag set by Refresh_Time_Flags.
      if Peer.Reactive_Keepalive_Due then
         return Send_Keepalive;
      end if;

      --  5. Persistent keepalive — unconditional periodic empty packet.
      --  Per WireGuard §6.5: if configured (> 0), send a keepalive
      --  whenever we haven't sent anything for Persistent_Keepalive_Ms
      --  ms.  This keeps NAT mappings and stateful firewalls open.
      --
      --  Step 6b.1: read the transition flag set by Refresh_Time_Flags
      --  rather than recomputing Now - Last_Sent.  Mark_Sent and
      --  Set_Persistent_Keepalive clear the flag, so the next fire is
      --  bounded by the wrapper re-running Refresh_Time_Flags after
      --  the deadline elapses.
      if Peer.Persistent_Keepalive_Due then
         return Send_Keepalive;
      end if;

      return No_Action;
   end Tick;

   ---------------------------------------------------------------------------
   --  Tick_All — Evaluate all peers under lock
   ---------------------------------------------------------------------------

   procedure Tick_All (Now : Timer.Clock.Timestamp; Actions : out Action_Array)
   is
   begin
      Lock;

      for I in Peer_Index loop
         Refresh_Time_Flags (I, Now);
         Actions (I) := Tick (I, Now);
      end loop;

      Unlock;
   end Tick_All;

   ---------------------------------------------------------------------------
   --  On_Peer_Timer_Due — Single-peer locked tick
   ---------------------------------------------------------------------------

   procedure On_Peer_Timer_Due
     (Peer_Idx      : Peer_Index;
      Now           : Timer.Clock.Timestamp;
      Action        : out Timer_Action;
      Next_Deadline : out Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Refresh_Time_Flags (Peer_Idx, Now);
      Action        := Tick (Peer_Idx, Now);
      Next_Deadline := Session.Timers.Next_Deadline (Peer_Idx, Now);
      Unlock;
   end On_Peer_Timer_Due;

   ---------------------------------------------------------------------------
   --  Locked_Next_Deadline — Single-peer locked deadline query
   ---------------------------------------------------------------------------

   procedure Locked_Next_Deadline
     (Peer_Idx      : Peer_Index;
      Now           : Timer.Clock.Timestamp;
      Next_Deadline : out Timer.Clock.Timestamp)
   is
   begin
      Lock;
      Next_Deadline := Session.Timers.Next_Deadline (Peer_Idx, Now);
      Unlock;
   end Locked_Next_Deadline;

   ---------------------------------------------------------------------------
   --  Next_Deadline helpers
   ---------------------------------------------------------------------------

   --  Minimum of two deadlines, treating Never as +infinity.
   function Earliest
     (A, B : Timer.Clock.Timestamp) return Timer.Clock.Timestamp
   is
   begin
      if A = Timer.Clock.Never then
         return B;
      end if;
      if B = Timer.Clock.Never then
         return A;
      end if;
      if A <= B then
         return A;
      else
         return B;
      end if;
   end Earliest;

   --  Force a deadline to be >= Now (or Never).  A deadline that has
   --  already passed becomes "due now"; Never stays Never.
   function Clamp_Future
     (T : Timer.Clock.Timestamp; Now : Timer.Clock.Timestamp)
      return Timer.Clock.Timestamp
   with Post =>
     Clamp_Future'Result = Timer.Clock.Never
     or else Clamp_Future'Result >= Now
   is
   begin
      if T = Timer.Clock.Never then
         return Timer.Clock.Never;
      end if;
      if T < Now then
         return Now;
      end if;
      return T;
   end Clamp_Future;

   ---------------------------------------------------------------------------
   --  Next_Deadline — Earliest re-evaluation point for one peer
   --
   --  Mirrors Tick's structure: walks every time-based condition that
   --  Tick consults and reports the minimum deadline.  Counter-based
   --  triggers (Send_Counter limits) are NOT modelled — see spec.
   ---------------------------------------------------------------------------

   function Next_Deadline
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp)
      return Timer.Clock.Timestamp
   is
      Peer : Peer_State renames Peers (Peer_Idx);
      D    : Timer.Clock.Timestamp := Timer.Clock.Never;
   begin
      --  Chunk 7d: walk the eight per-condition deadlines stamped by
      --  the transitions in Session.  Earliest treats Never as
      --  +infinity, so unarmed deadlines are skipped automatically.
      D := Earliest (D, Peer.Persistent_Keepalive_Deadline);
      D := Earliest (D, Peer.Reactive_Keepalive_Deadline);
      D := Earliest (D, Peer.Unresponsive_Peer_Deadline);
      D := Earliest (D, Peer.Zero_Keys_Deadline);
      D := Earliest (D, Peer.Session_Expire_Time_Deadline);
      D := Earliest (D, Peer.Rekey_Time_Deadline);
      D := Earliest (D, Peer.Rekey_Timed_Out_Deadline);
      D := Earliest (D, Peer.Rekey_Retry_Deadline);

      --  Counter-driven triggers — not time-predictable but become
      --  true synchronously inside wg_send/wg_receive when
      --  Send_Counter crosses the limit.  After chunk 3, every such
      --  call is followed by rearm_peer_timer, so reflecting the
      --  crossing as "deadline = Now" makes the next esp_timer fire
      --  immediately and Tick dispatches Initiate_Rekey or
      --  Session_Expired without waiting for a separate periodic
      --  recheck.
      if Peer.Active
        and then Peer.Current.Valid
        and then (Peer.Current.Send_Counter >= Reject_After_Messages
                  or else Peer.Current.Send_Counter >= Rekey_After_Messages)
      then
         D := Earliest (D, Now);
      end if;

      return Clamp_Future (D, Now);
   end Next_Deadline;

end Session.Timers;
