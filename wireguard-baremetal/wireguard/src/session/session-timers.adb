--  Session.Timers — Implementation

package body Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Elapsed — Milliseconds since a timestamp (clamped to 0)
   ---------------------------------------------------------------------------

   function Elapsed
     (Start : Timer.Clock.Timestamp; Now : Timer.Clock.Timestamp)
      return Unsigned_64
   with Post => (if Now > Start then Elapsed'Result > 0)
   is
   begin
      if Now <= Start then
         return 0;
      end if;
      return Now - Start;
   end Elapsed;

   ---------------------------------------------------------------------------
   --  Refresh_Time_Flags — Recompute time-based transition flags
   --
   --  Single owner of all Now-based arithmetic for Tick.  Called at
   --  the entry of Tick_All and On_Peer_Timer_Due so the flags are
   --  always live when Tick runs.  Each call fully recomputes (set
   --  or clear); transitions therefore do not need to eagerly clear
   --  the flags.
   --
   --  After step 6b.4, every elapsed-time threshold that Tick used
   --  to compute inline lives here as a single Boolean.  Tick
   --  consumes only flags, counters, and the discrete Mode/Active
   --  bits — no Now arithmetic.
   ---------------------------------------------------------------------------

   procedure Refresh_Time_Flags
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp)
   is
      Peer : Peer_State renames Peers (Peer_Idx);
   begin
      --  Persistent keepalive: deadline elapsed since last send.
      Peer.Persistent_Keepalive_Due :=
        Peer.Persistent_Keepalive_Ms > 0
        and then Elapsed (Peer.Last_Sent, Now)
                   >= Peer.Persistent_Keepalive_Ms;

      --  Reactive keepalive: received recently, haven't sent back
      --  within the keepalive window.  Both edges of the window
      --  are time-based, so the flag is set or cleared by this
      --  recomputation alone.
      Peer.Reactive_Keepalive_Due :=
        Peer.Last_Received /= Timer.Clock.Never
        and then Elapsed (Peer.Last_Received, Now) < Keepalive_Timeout_Ms
        and then Elapsed (Peer.Last_Sent, Now) >= Keepalive_Timeout_Ms;

      --  Unresponsive peer probe (§6.5 last paragraph): we sent DATA
      --  and got no authenticated reply within New_Handshake_Time_Ms.
      --  Last_Data_Sent is set only for real payloads, so reactive
      --  keepalives never trigger this.
      Peer.Unresponsive_Peer_Due :=
        Peer.Last_Data_Sent /= Timer.Clock.Never
        and then Peer.Last_Data_Sent > Peer.Last_Received
        and then Elapsed (Peer.Last_Data_Sent, Now)
                   >= New_Handshake_Time_Ms;

      --  Key zeroing (§6.3 last sentence): erase all keys 3×Reject
      --  after the last handshake.  Applies even to inactive peers
      --  as long as Last_Handshake is still set (the Zero_All_Keys
      --  handler clears it via Clear_Handshake_Timestamp).
      Peer.Zero_Keys_Due :=
        Peer.Last_Handshake /= Timer.Clock.Never
        and then not Peer.Active
        and then Elapsed (Peer.Last_Handshake, Now) >= Key_Zeroing_After_Ms;

      --  Hard time expiry of the current keypair.  Counter-based
      --  Reject_After_Messages stays inline in Tick (counter, not
      --  time).  Only meaningful when there is a current keypair.
      Peer.Session_Expire_Time_Due :=
        Peer.Active
        and then Peer.Current.Valid
        and then Elapsed (Peer.Current.Created_At, Now)
                   >= Reject_After_Time_Ms;

      --  Initiator-only time-based rekey, send side (§6.2 ¶2) at
      --  Rekey_After_Time_Ms (120 s) and receive side at
      --  Reject_After_Time_Ms - Keepalive - Rekey (165 s).
      Peer.Rekey_Time_Due :=
        Peer.Active
        and then Peer.Current.Valid
        and then Peer.Mode = Established
        and then Peer.Is_Initiator
        and then
          (Elapsed (Peer.Current.Created_At, Now) >= Rekey_After_Time_Ms
           or else
             Elapsed (Peer.Current.Created_At, Now)
               >= Reject_After_Time_Ms
                    - Keepalive_Timeout_Ms
                    - Rekey_Timeout_Ms);

      --  Rekey attempt window exhausted (§6.4): only meaningful in
      --  Rekeying mode where Rekey_Start /= Never (Valid_Peer).
      Peer.Rekey_Timed_Out_Due :=
        Peer.Mode = Rekeying
        and then Elapsed (Peer.Rekey_Start, Now) >= Rekey_Attempt_Time_Ms;

      --  Rekey retry gating (§6.1): re-initiate after
      --  Rekey_Timeout_Ms + Rekey_Jitter_Ms.
      Peer.Rekey_Retry_Due :=
        Peer.Mode = Rekeying
        and then Elapsed (Peer.Rekey_Last_Sent, Now)
                   >= Rekey_Timeout_Ms + Peer.Rekey_Jitter_Ms;
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

   --  Saturating add for Timer.Clock.Timestamp arithmetic.  Used to
   --  compute Start + Delay without wrapping.  Caps at Timestamp'Last,
   --  which is treated as a finite (very far-future) deadline by
   --  Earliest, never as Never.
   function Add_Capped
     (Start : Timer.Clock.Timestamp; D : Unsigned_64)
      return Timer.Clock.Timestamp
   with Post => Add_Capped'Result >= Start
   is
   begin
      if Timer.Clock.Timestamp'Last - Start <= D then
         return Timer.Clock.Timestamp'Last;
      end if;
      return Start + D;
   end Add_Capped;

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
      Peer : constant Peer_State := Peers (Peer_Idx);
      D    : Timer.Clock.Timestamp := Timer.Clock.Never;
   begin
      --  1. Key zeroing — applies even to inactive peers as long as
      --  Last_Handshake is still set.
      if Peer.Last_Handshake /= Timer.Clock.Never
        and then not Peer.Active
      then
         D := Earliest
                (D, Add_Capped (Peer.Last_Handshake, Key_Zeroing_After_Ms));
      end if;

      --  Inactive / no current keypair: only key-zeroing matters.
      if not Peer.Active or else not Peer.Current.Valid then
         return Clamp_Future (D, Now);
      end if;

      --  2. Hard expiry — Reject_After_Time
      D := Earliest
             (D, Add_Capped (Peer.Current.Created_At, Reject_After_Time_Ms));

      --  Counter-driven triggers — these are NOT time-predictable
      --  but become true synchronously inside wg_send/wg_receive when
      --  Send_Counter crosses the limit.  After chunk 3, every such
      --  call is followed by rearm_peer_timer, so reflecting the
      --  crossing as "deadline = Now" makes the next esp_timer fire
      --  immediately and Tick dispatches Initiate_Rekey or
      --  Session_Expired without waiting for a separate periodic
      --  recheck.
      if Peer.Current.Send_Counter >= Reject_After_Messages
        or else Peer.Current.Send_Counter >= Rekey_After_Messages
      then
         D := Earliest (D, Now);
      end if;

      case Peer.Mode is
         when Established =>
            --  Time-based rekey, initiator only
            if Peer.Is_Initiator then
               D := Earliest
                      (D,
                       Add_Capped (Peer.Current.Created_At,
                                   Rekey_After_Time_Ms));
               D := Earliest
                      (D,
                       Add_Capped (Peer.Current.Created_At,
                                   Reject_After_Time_Ms
                                   - Keepalive_Timeout_Ms
                                   - Rekey_Timeout_Ms));
            end if;

            --  Unresponsive-peer probe: only meaningful while
            --  Last_Data_Sent > Last_Received.
            if Peer.Last_Data_Sent /= Timer.Clock.Never
              and then Peer.Last_Data_Sent > Peer.Last_Received
            then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Data_Sent,
                                      New_Handshake_Time_Ms));
            end if;

            --  Reactive keepalive (idle responder side).
            if Peer.Last_Received /= Timer.Clock.Never then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Sent, Keepalive_Timeout_Ms));
            end if;

            --  Persistent keepalive.
            if Peer.Persistent_Keepalive_Ms > 0 then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Sent,
                                      Peer.Persistent_Keepalive_Ms));
            end if;

         when Rekeying =>
            D := Earliest
                   (D, Add_Capped (Peer.Rekey_Start, Rekey_Attempt_Time_Ms));
            D := Earliest
                   (D, Add_Capped (Peer.Rekey_Last_Sent,
                                   Rekey_Timeout_Ms + Peer.Rekey_Jitter_Ms));

         when Inactive =>
            null;
      end case;

      return Clamp_Future (D, Now);
   end Next_Deadline;

end Session.Timers;
