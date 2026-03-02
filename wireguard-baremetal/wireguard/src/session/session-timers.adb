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
       -- Established rekey: initiator-only for time, any peer for counter
       and then
         (if Tick'Result = Initiate_Rekey
            and then Peers (Peer_Idx).Mode = Established
          then
            Peers (Peer_Idx).Is_Initiator
            or else
              Peers (Peer_Idx).Current.Send_Counter >= Rekey_After_Messages)
   is
      Peer : constant Peer_State := Peers (Peer_Idx);
      Age  : Unsigned_64;
   begin
      --  Inactive/invalid peers need nothing
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

            --  Retry gating: re-send initiation every 5 s
            declare
               Since_Last : constant Unsigned_64 :=
                 Elapsed (Peer.Rekey_Last_Sent, Now);
            begin
               if Since_Last >= Rekey_Timeout_S then
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

end Session.Timers;
