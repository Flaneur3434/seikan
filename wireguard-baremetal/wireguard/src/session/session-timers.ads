--  Session.Timers — WireGuard Timer Decision Logic
--
--  Pure decision: given current time + peer state, returns what C
--  needs to do.  Priority is implicit in evaluation order:
--
--    Session_Expired > Rekey_Timed_Out > Initiate_Rekey > Send_Keepalive
--
--  Everything else (timestamps, replay, counters) is Ada-internal
--  and happens passively in the normal packet flow.

package Session.Timers
  with SPARK_Mode => On
is

   --  The only actions C needs to act on.
   --  One action per peer per tick — mutually exclusive.
   type Timer_Action is
     (No_Action,
      Send_Keepalive,
      Initiate_Rekey,
      Rekey_Timed_Out,
      Session_Expired);

   function Tick
     (Peer_Idx : Peer_Index;
      Now      : Timer.Clock.Timestamp) return Timer_Action
   with Pre => Now > Timer.Clock.Never;

   type Action_Array is array (Peer_Index) of Timer_Action;

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Action_Array)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre =>
       Session_Ready
       and then Now > Timer.Clock.Never;

end Session.Timers;
