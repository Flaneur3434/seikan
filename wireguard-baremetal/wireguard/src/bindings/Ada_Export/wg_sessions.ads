--  WG_Sessions - C FFI for session operations
--
--  Exports Ada session management to C for FreeRTOS integration.
--  C owns: static semaphore, timer task, protocol task, queues.
--  Ada owns: all session state, timer evaluation, crypto.

with Interfaces;
with Interfaces.C;
with Session;
with Threads.Mutex;

package WG_Sessions
   with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Initialization
   ---------------------------------------------------------------------------

   --  Create mutex from static semaphore, zero session tables.
   procedure C_Session_Init
     (Sem : not null Threads.Mutex.Semaphore_Ref)
   with Export,
        Convention    => C,
        External_Name => "session_init",
        SPARK_Mode    => Off;

   ---------------------------------------------------------------------------
   --  Timer tick — called once/second by the timer task (pri 7)
   ---------------------------------------------------------------------------

   --  Maps to Ada Timer_Action enum.
   --  C sees: 0=none, 1=keepalive, 2=rekey, 3=rekey_timeout, 4=expired
   subtype C_Timer_Action is Interfaces.Unsigned_8;

   type C_Action_Array is
     array (0 .. Session.Max_Peers - 1) of C_Timer_Action
   with Convention => C;

   --  Evaluate all peer timers under a single lock hold.
   --  Fills Actions[0..Max_Peers-1].  C index 0 = Peer 1.
   procedure C_Session_Tick_All
     (Now     : Interfaces.Unsigned_64;
      Actions : out C_Action_Array)
   with Export,
        Convention    => C,
        External_Name => "session_tick_all",
        SPARK_Mode    => Off;

   --  Single-peer timer evaluation. Used by the timer-driven urgent
   --  path: the C wg_urgent task calls this for each peer whose
   --  esp_timer expired. Acquires the session mutex internally.
   --
   --  Out_Action receives the Timer_Action enum (0..5).
   --  Out_Next_Deadline_Ms receives the earliest absolute Now
   --  (milliseconds since boot) at which C should re-evaluate this
   --  peer.  0 means "no time-based deadline meaningful for this
   --  peer right now" (Timer.Clock.Never).  Both outputs are set
   --  under one lock hold so they are an atomic snapshot of peer
   --  state at Now.
   --
   --  If Peer is out of range, both outputs are set to 0 (defensive).
   procedure C_Session_On_Peer_Timer_Due
     (Peer                 : Interfaces.C.unsigned;
      Now                  : Interfaces.Unsigned_64;
      Out_Action           : access Interfaces.Unsigned_8;
      Out_Next_Deadline_Ms : access Interfaces.Unsigned_64)
   with Export,
        Convention    => C,
        External_Name => "session_on_peer_timer_due",
        SPARK_Mode    => Off;

   --  Single-peer next-deadline query.  Used by the C wg_proto task
   --  to re-arm a peer's esp_timer right after each Ada state-
   --  mutating call.  Acquires the session mutex internally.
   --
   --  Out_Next_Deadline_Ms receives the earliest absolute Now
   --  (milliseconds) at which the peer should be re-evaluated, or 0
   --  if no time-based deadline is currently meaningful (Never).
   --
   --  If Peer is out of range or Out_Next_Deadline_Ms is null, the
   --  call is a no-op (output is set to 0 if peer is out of range
   --  but pointer is valid).
   procedure C_Session_Next_Deadline
     (Peer                 : Interfaces.C.unsigned;
      Now                  : Interfaces.Unsigned_64;
      Out_Next_Deadline_Ms : access Interfaces.Unsigned_64)
   with Export,
        Convention    => C,
        External_Name => "session_next_deadline",
        SPARK_Mode    => Off;

   ---------------------------------------------------------------------------
   --  Session query — is the peer's current keypair valid?
   ---------------------------------------------------------------------------

   --  Returns 1 if the peer has a valid current keypair, 0 otherwise.
   function C_Session_Is_Active
     (Peer : Interfaces.C.unsigned)
      return Interfaces.C.unsigned_char
   with Export,
        Convention    => C,
        External_Name => "wg_session_is_active",
        SPARK_Mode    => Off;

end WG_Sessions;
