--  Session.Timers — Implementation

package body Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Elapsed — Seconds since a timestamp (clamped to 0)
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
       -- Priority: expired dominates everything
       (if Tick'Result = Session_Expired
        then
          Elapsed (Peers (Peer_Idx).Current.Created_At, Now)
          >= Reject_After_Time_S
          or else
            Peers (Peer_Idx).Current.Send_Counter >= Reject_After_Messages)
       -- Priority: timed_out dominates rekey
       and then
         (if Tick'Result = Initiate_Rekey
            and then Peers (Peer_Idx).Mode = Rekeying
          then
            Elapsed (Peers (Peer_Idx).Rekey_Start, Now) < Rekey_Attempt_Time_S)
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
              (Peers (Peer_Idx).Last_Data_Sent /= Timer.Clock.Never
               and then
                 Peers (Peer_Idx).Last_Data_Sent
                 > Peers (Peer_Idx).Last_Received
               and then
                 Elapsed (Peers (Peer_Idx).Last_Data_Sent, Now)
                 >= New_Handshake_Time_S))
   is
      Peer : constant Peer_State := Peers (Peer_Idx);
      Age  : Unsigned_64;
   begin
      --  Key zeroing at 3×Reject (540 s) — §6.3 last sentence
      --  Even for inactive/expired peers: if Last_Handshake is still set,
      --  erase all remaining cryptographic material after 540 s.
      --  The Zero_All_Keys handler clears Last_Handshake to prevent
      --  re-firing.
      if Peer.Last_Handshake /= Timer.Clock.Never
        and then not Peer.Active
        and then Elapsed (Peer.Last_Handshake, Now) >= Key_Zeroing_After_S
      then
         return Zero_All_Keys;
      end if;

      --  Inactive/invalid peers need nothing (below 540 s threshold)
      if not Peer.Active or else not Peer.Current.Valid then
         return No_Action;
      end if;

      Age := Elapsed (Peer.Current.Created_At, Now);

      --  Hard expiry — reject-after limits
      if Age >= Reject_After_Time_S
        or else Peer.Current.Send_Counter >= Reject_After_Messages
      then
         return Session_Expired;
      end if;

      case Peer.Mode is
         when Established =>
            --  Counter-based rekey: ANY peer (§6.2 paragraph 1).
            --  "WireGuard will try to create a new session … after
            --  it has sent Rekey-After-Messages transport data messages."
            --  No initiator restriction — matches wireguard-go
            --  keepKeyFreshSending(): nonce > RekeyAfterMessages.
            if Peer.Current.Send_Counter >= Rekey_After_Messages then
               return Initiate_Rekey;
            end if;

            --  Time-based rekey: ONLY initiator (§6.2 paragraph 2).
            --  Prevents the "thundering herd" problem where both
            --  peers try to establish a new session simultaneously.
            if Peer.Is_Initiator then
               --  After SENDING: session >= Rekey_After_Time (120 s)
               --  Matches wireguard-go keepKeyFreshSending():
               --    keypair.isInitiator && age > RekeyAfterTime
               if Age >= Rekey_After_Time_S then
                  return Initiate_Rekey;
               end if;

               --  After RECEIVING: session >= Reject − Keepalive − Rekey
               --  (180 − 10 − 5 = 165 s).  One-shot by construction:
               --  first Initiate_Rekey → Rekeying, so Established
               --  branch never fires again.
               --  Matches wireguard-go keepKeyFreshReceiving().
               if Age >= Reject_After_Time_S
                            - Keepalive_Timeout_S
                            - Rekey_Timeout_S
               then
                  return Initiate_Rekey;
               end if;
            end if;

            --  Unresponsive peer detection — §6.5 last paragraph
            --  Matches wireguard-go expiredNewHandshake (15 s).
            --  If we sent DATA (not just keepalive) and got no
            --  authenticated reply in New_Handshake_Time (15 s),
            --  initiate a handshake to probe peer liveness.
            --  Uses Last_Data_Sent (set only for real payloads)
            --  so reactive keepalives don't trigger false positives.
            if Peer.Last_Data_Sent /= Timer.Clock.Never
              and then Peer.Last_Data_Sent > Peer.Last_Received
              and then Elapsed (Peer.Last_Data_Sent, Now)
                       >= New_Handshake_Time_S
            then
               return Initiate_Rekey;
            end if;

         when Rekeying    =>
            --  Rekey attempt timed out (90 s window exhausted)
            --  Must be checked BEFORE retry gating so we don't
            --  keep retrying after the attempt window is exhausted.
            declare
               Attempt_Elapsed : constant Unsigned_64 :=
                 Elapsed (Peer.Rekey_Start, Now);
            begin
               if Attempt_Elapsed >= Rekey_Attempt_Time_S then
                  return Rekey_Timed_Out;
               end if;
            end;

            --  Retry gating: re-send initiation every 5 + jitter s
            --  Jitter (0..2 s) prevents lock-step retransmissions (§6.1).
            declare
               Since_Last : constant Unsigned_64 :=
                 Elapsed (Peer.Rekey_Last_Sent, Now);
            begin
               if Since_Last >= Rekey_Timeout_S + Peer.Rekey_Jitter_S then
                  return Initiate_Rekey;
               end if;
            end;

         when Inactive    =>
            null;
      end case;

      --  4. Reactive keepalive — received recently, haven't sent back
      if Peer.Last_Received /= Timer.Clock.Never then
         declare
            Since_Recv : constant Unsigned_64 :=
              Elapsed (Peer.Last_Received, Now);
            Since_Sent : constant Unsigned_64 := Elapsed (Peer.Last_Sent, Now);
         begin
            if Since_Recv < Keepalive_Timeout_S
              and then Since_Sent >= Keepalive_Timeout_S
            then
               return Send_Keepalive;
            end if;
         end;
      end if;

      --  5. Persistent keepalive — unconditional periodic empty packet.
      --  Per WireGuard §6.5: if configured (> 0), send a keepalive
      --  whenever we haven't sent anything for Persistent_Keepalive_S
      --  seconds.  This keeps NAT mappings and stateful firewalls open.
      if Peer.Persistent_Keepalive_S > 0 then
         declare
            Since_Sent : constant Unsigned_64 :=
              Elapsed (Peer.Last_Sent, Now);
         begin
            if Since_Sent >= Peer.Persistent_Keepalive_S then
               return Send_Keepalive;
            end if;
         end;
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
         Actions (I) := Tick (I, Now);
      end loop;

      Unlock;
   end Tick_All;

   ---------------------------------------------------------------------------
   --  On_Peer_Timer_Due — Single-peer locked tick
   ---------------------------------------------------------------------------

   procedure On_Peer_Timer_Due
     (Peer_Idx : Peer_Index;
      Now      : Timer.Clock.Timestamp;
      Action   : out Timer_Action)
   is
   begin
      Lock;
      Action := Tick (Peer_Idx, Now);
      Unlock;
   end On_Peer_Timer_Due;

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
                (D, Add_Capped (Peer.Last_Handshake, Key_Zeroing_After_S));
      end if;

      --  Inactive / no current keypair: only key-zeroing matters.
      if not Peer.Active or else not Peer.Current.Valid then
         return Clamp_Future (D, Now);
      end if;

      --  2. Hard expiry — Reject_After_Time
      D := Earliest
             (D, Add_Capped (Peer.Current.Created_At, Reject_After_Time_S));

      case Peer.Mode is
         when Established =>
            --  Time-based rekey, initiator only
            if Peer.Is_Initiator then
               D := Earliest
                      (D,
                       Add_Capped (Peer.Current.Created_At,
                                   Rekey_After_Time_S));
               D := Earliest
                      (D,
                       Add_Capped (Peer.Current.Created_At,
                                   Reject_After_Time_S
                                   - Keepalive_Timeout_S
                                   - Rekey_Timeout_S));
            end if;

            --  Unresponsive-peer probe: only meaningful while
            --  Last_Data_Sent > Last_Received.
            if Peer.Last_Data_Sent /= Timer.Clock.Never
              and then Peer.Last_Data_Sent > Peer.Last_Received
            then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Data_Sent,
                                      New_Handshake_Time_S));
            end if;

            --  Reactive keepalive (idle responder side).
            if Peer.Last_Received /= Timer.Clock.Never then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Sent, Keepalive_Timeout_S));
            end if;

            --  Persistent keepalive.
            if Peer.Persistent_Keepalive_S > 0 then
               D := Earliest
                      (D, Add_Capped (Peer.Last_Sent,
                                      Peer.Persistent_Keepalive_S));
            end if;

         when Rekeying =>
            D := Earliest
                   (D, Add_Capped (Peer.Rekey_Start, Rekey_Attempt_Time_S));
            D := Earliest
                   (D, Add_Capped (Peer.Rekey_Last_Sent,
                                   Rekey_Timeout_S + Peer.Rekey_Jitter_S));

         when Inactive =>
            null;
      end case;

      return Clamp_Future (D, Now);
   end Next_Deadline;

end Session.Timers;
