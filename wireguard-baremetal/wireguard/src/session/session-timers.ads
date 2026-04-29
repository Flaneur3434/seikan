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

   --  Refresh_Time_Flags — Recompute time-based transition flags
   --  for Peer_Idx from Now and stored timestamps.  Sets the
   --  Persistent_Keepalive_Due flag in Peers when the deadline has
   --  elapsed; leaves it unchanged otherwise (Mark_Sent /
   --  Set_Persistent_Keepalive clear it on every relevant transition).
   --
   --  Step 6b.1 of the timer-driven migration: this is the bridge
   --  that lets Tick read the flag instead of computing
   --  Now - Last_Sent >= Persistent_Keepalive_Ms.  Future steps
   --  will fold the remaining arithmetic checks into this routine
   --  and remove them from Tick.
   --
   --  Caller must hold the session mutex.
   procedure Refresh_Time_Flags
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp)
   with
     Global => (In_Out => Peer_States),
     Pre    => Now > Timer.Clock.Never and then All_Peers_Valid,
     Post   => All_Peers_Valid;

   type Action_Array is array (Peer_Index) of Timer_Action;

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Action_Array)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre  =>
       Session_Ready
       and then Now > Timer.Clock.Never,
     Post =>
       Session_Ready;

   --  On_Peer_Timer_Due — Single-peer locked tick.
   --
   --  Used by the C wg_urgent task when an esp_timer expiry marks a
   --  specific peer as due. Functionally equivalent to Tick_All but
   --  evaluates one peer only, eliminating the per-tick scan over
   --  WG_MAX_PEERS that the polling path requires.
   --
   --  Acquires and releases Mutex_State internally; safe to call from
   --  any task. The returned Action is what the caller should
   --  immediately dispatch (typically via wg_dispatch_timer in C).
   --
   --  Next_Deadline is the earliest absolute timestamp at which the
   --  caller should re-evaluate this peer (= Session.Timers.Next_Deadline
   --  applied at the same Now, evaluated under the same lock hold so
   --  the two values are an atomic snapshot).  Timer.Clock.Never means
   --  no time-based deadline is currently meaningful for this peer.
   procedure On_Peer_Timer_Due
     (Peer_Idx      : Peer_Index;
      Now           : Timer.Clock.Timestamp;
      Action        : out Timer_Action;
      Next_Deadline : out Timer.Clock.Timestamp)
   with
     Global => (In_Out => (Peer_States, Mutex_State)),
     Pre    =>
       Session_Ready
       and then Now > Timer.Clock.Never,
     Post   =>
       Session_Ready
       and then
         (Next_Deadline = Timer.Clock.Never
          or else Next_Deadline >= Now);

   --  Locked_Next_Deadline — Same as Next_Deadline but takes the
   --  session mutex internally.  Used by the C wg_proto task to
   --  re-arm a peer's esp_timer immediately after a state-mutating
   --  Ada call (wg_send, wg_auto_handshake, wg_create_response,
   --  wg_receive_netif), so the deadline reflects the new state
   --  without waiting for the next wg_urgent wake.
   procedure Locked_Next_Deadline
     (Peer_Idx      : Peer_Index;
      Now           : Timer.Clock.Timestamp;
      Next_Deadline : out Timer.Clock.Timestamp)
   with
     Global => (Input => Peer_States, In_Out => Mutex_State),
     Pre    =>
       Session_Ready
       and then Now > Timer.Clock.Never,
     Post   =>
       Is_Mtx_Initialized and then not Is_Mtx_Locked
       and then
         (Next_Deadline = Timer.Clock.Never
          or else Next_Deadline >= Now);

   --  Next_Deadline — When should this peer be re-evaluated?
   --
   --  Returns the earliest absolute Now at which Tick would (or might)
   --  produce a non-No_Action result for Peer_Idx, given the peer's
   --  current state.
   --
   --  Counter-driven triggers (Send_Counter >= Rekey_After_Messages /
   --  Reject_After_Messages) become true synchronously inside
   --  wg_send/wg_receive.  After every such call, wg_proto re-arms
   --  via session_next_deadline; if the counter has already crossed
   --  the limit, this function returns Now so the timer fires
   --  immediately.  Callers therefore do NOT need a separate periodic
   --  recheck cap.
   --
   --  If no time-based deadline is currently meaningful for the peer
   --  (e.g. Inactive peer with no Last_Handshake, no persistent
   --  keepalive), Timer.Clock.Never is returned. C interprets that
   --  as "do not arm a timer for this peer."
   function Next_Deadline
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp)
      return Timer.Clock.Timestamp
   with
     Global => (Input => Peer_States),
     Pre    => Now > Timer.Clock.Never,
     Post   =>
       Next_Deadline'Result = Timer.Clock.Never
       or else Next_Deadline'Result >= Now;

end Session.Timers;
