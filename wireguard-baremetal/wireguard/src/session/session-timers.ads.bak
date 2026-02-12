--  Session.Timer - WireGuard Timer Event State Machine
--
--  Pure decision logic: given current time and peer state, determines
--  which timer actions are needed.  No I/O, no side effects — just
--  boolean flags the C layer enqueues for the WG task.
--
--  Called once per second by the timer task (priority 7) under the
--  session mutex.  The WG task (priority 6) drains the resulting
--  action queue non-blocking at the top of its loop.
--
--  Timer events from the WireGuard whitepaper §6.1–6.4:
--
--    Send_Keepalive      — No packet sent for Keepalive_Timeout seconds
--                          after last received packet
--    Initiate_Rekey      — Current session older than Rekey_After_Time,
--                          or send counter approaching Rekey_After_Messages
--    Session_Expired     — Current session older than Reject_After_Time,
--                          or send counter exceeded Reject_After_Messages
--    Rekey_Timed_Out     — Rekey attempt exceeded Rekey_Attempt_Time
--    Handshake_Timed_Out — No response to initiation for Rekey_Timeout

package Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Timer_Action — Set of flags indicating what the WG task should do
   --
   --  The timer task produces one of these per peer per tick.
   --  If all flags are False, no action is needed.
   ---------------------------------------------------------------------------

   type Timer_Action is record
      Send_Keepalive      : Boolean;
      Initiate_Rekey      : Boolean;
      Session_Expired     : Boolean;
      Rekey_Timed_Out     : Boolean;
   end record;

   No_Action : constant Timer_Action :=
     (Send_Keepalive      => False,
      Initiate_Rekey      => False,
      Session_Expired     => False,
      Rekey_Timed_Out     => False);

   ---------------------------------------------------------------------------
   --  Tick — Evaluate one peer's timer state
   --
   --  Pure function: reads peer state + current time, returns actions.
   --  Does NOT modify peer state.  The WG task applies the results.
   --
   --  Caller must hold the session mutex.
   ---------------------------------------------------------------------------

   function Tick
     (Peer : Peer_State;
      Now  : Timer.Clock.Timestamp) return Timer_Action
     with Pre  => Now > Timer.Clock.Never,
          Post =>
            --  Session_Expired is exclusive: all other flags are False.
            --  An expired session early-returns before any rekey/keepalive
            --  checks, so no other action can be set alongside it.
            (if Tick'Result.Session_Expired
             then not Tick'Result.Initiate_Rekey
                  and then not Tick'Result.Send_Keepalive
                  and then not Tick'Result.Rekey_Timed_Out);
   --  Precondition: Now > 0 (system has booted).

   ---------------------------------------------------------------------------
   --  Tick_All — Evaluate all active peers, return actions per peer
   ---------------------------------------------------------------------------

   type Action_Array is array (Peer_Index) of Timer_Action;

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Action_Array)
   with Pre => Is_Mtx_Initialized and then not Is_Mtx_Locked
               and then Now > Timer.Clock.Never;
   --  Evaluate all peers under lock.  Caller must not hold the mutex.

end Session.Timers;
