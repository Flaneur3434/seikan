--  Session.Timers — WireGuard Timer Decision Logic
--
--  Pure decision: given current time + peer state, returns what C
--  needs to do.  Priority is implicit in evaluation order:
--
--    Zero_All_Keys > Session_Expired > Rekey_Timed_Out >
--    Initiate_Rekey > Send_Keepalive
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
      Session_Expired,
      Zero_All_Keys);

   function Tick
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp) return Timer_Action
   with
     Global => (Input => Peer_States),
     Pre    => Now > Timer.Clock.Never;

   type Action_Array is array (Peer_Index) of Timer_Action;

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Action_Array)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre  =>
       Session_Ready
       and then Now > Timer.Clock.Never,
     Post =>
       Is_Mtx_Initialized and then not Is_Mtx_Locked;

   --  On_Peer_Timer_Due — Single-peer locked tick.
   --
   --  Used by the C wg_urgent task when an esp_timer expiry marks a
   --  specific peer as due. Functionally equivalent to Tick_All but
   --  evaluates one peer only, eliminating the per-tick scan over
   --  WG_MAX_PEERS that the polling path requires.
   --
   --  Acquires and releases Mutex_State internally; safe to call from
   --  any task. The returned action is what the caller should
   --  immediately dispatch (typically via wg_dispatch_timer in C).
   procedure On_Peer_Timer_Due
     (Peer_Idx : Peer_Index;
      Now      : Timer.Clock.Timestamp;
      Action   : out Timer_Action)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre    =>
       Session_Ready
       and then Now > Timer.Clock.Never,
     Post   =>
       Is_Mtx_Initialized and then not Is_Mtx_Locked;

end Session.Timers;
