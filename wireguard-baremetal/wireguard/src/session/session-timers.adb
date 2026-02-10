--  Session.Timer - Implementation

package body Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Elapsed — Compute seconds elapsed since a timestamp
   --
   --  Returns 0 if Start is Never (event hasn't occurred yet).
   ---------------------------------------------------------------------------

   function Elapsed
     (Start : Timer.Clock.Timestamp;
      Now   : Timer.Clock.Timestamp) return Unsigned_64
   is
   begin
      if Start = Timer.Clock.Never or else Now < Start then
         return 0;
      end if;
      return Now - Start;
   end Elapsed;

   ---------------------------------------------------------------------------
   --  Tick — Evaluate one peer's timer conditions
   ---------------------------------------------------------------------------

   function Tick
     (Peer : Peer_State;
      Now  : Timer.Clock.Timestamp) return Timer_Action
   is
      A : Timer_Action := No_Action;
      Age : Unsigned_64;
   begin
      --  Skip inactive peers
      if not Peer.Active or else not Peer.Current.Valid then
         return No_Action;
      end if;

      --  How old is the current session?
      Age := Elapsed (Peer.Current.Created_At, Now);

      --  1. Session expiry — Reject_After_Time exceeded
      --     This is the hardest deadline: drop the session entirely.
      if Age >= Reject_After_Time_S then
         A.Session_Expired := True;
         --  No point checking other timers if session is dead
         return A;
      end if;

      --  2. Message counter limits
      --     Reject_After_Messages → expire immediately
      --     Rekey_After_Messages  → initiate rekey
      if Peer.Current.Send_Counter >= Reject_After_Messages then
         A.Session_Expired := True;
         return A;
      end if;

      if Peer.Current.Send_Counter >= Rekey_After_Messages then
         if not Peer.Rekey_Attempted then
            A.Initiate_Rekey := True;
         end if;
      end if;

      --  3. Time-based rekey — Rekey_After_Time exceeded
      if Age >= Rekey_After_Time_S and then not Peer.Rekey_Attempted then
         A.Initiate_Rekey := True;
      end if;

      --  4. Rekey attempt timeout — Rekey_Attempt_Time exceeded
      --     If we started a rekey and it's taking too long, retry.
      if Peer.Rekey_Attempted then
         declare
            Attempt_Elapsed : constant Unsigned_64 :=
              Elapsed (Peer.Rekey_Attempt_Start, Now);
         begin
            if Attempt_Elapsed >= Rekey_Attempt_Time_S then
               A.Rekey_Timed_Out := True;
            end if;
         end;
      end if;

      --  5. Keepalive — We received a packet but haven't sent anything
      --     back within Keepalive_Timeout.  Send an empty data packet
      --     so the peer knows we're alive (NAT traversal).
      if Peer.Last_Received /= Timer.Clock.Never then
         declare
            Since_Recv : constant Unsigned_64 :=
              Elapsed (Peer.Last_Received, Now);
            Since_Sent : constant Unsigned_64 :=
              Elapsed (Peer.Last_Sent, Now);
         begin
            --  If we received recently but haven't sent recently enough
            if Since_Recv < Keepalive_Timeout_S
              and then Since_Sent >= Keepalive_Timeout_S
            then
               A.Send_Keepalive := True;
            end if;
         end;
      end if;

      return A;
   end Tick;

   ---------------------------------------------------------------------------
   --  Tick_All — Scan every active peer
   ---------------------------------------------------------------------------

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Action_Array)
   is
   begin
      Lock;
      for I in Peer_Index loop
         Actions (I) := Tick (Peers (I), Now);
      end loop;
      Unlock;
   end Tick_All;

end Session.Timers;
