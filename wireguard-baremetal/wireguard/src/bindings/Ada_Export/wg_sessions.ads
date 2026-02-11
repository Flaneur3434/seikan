--  WG_Sessions - C FFI for session operations
--
--  Exports Ada session management to C for FreeRTOS integration.
--  C owns: static semaphore, timer task, protocol task, queues.
--  Ada owns: all session state, timer evaluation, crypto.
--
--  Exported symbols:
--    session_init             — create mutex, zero tables
--    session_tick_all         — evaluate all peer timers
--    session_expire           — wipe all keypair slots
--    session_set_rekey_flag   — mark rekey in progress

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

   procedure C_Session_Init
     (Sem : not null Threads.Mutex.Semaphore_Ref)
   with Export,
        Convention    => C,
        External_Name => "session_init",
        SPARK_Mode    => Off;
   --  Create mutex from static semaphore, zero session tables.

   ---------------------------------------------------------------------------
   --  Timer tick — called once/second by the timer task (pri 7)
   ---------------------------------------------------------------------------

   type C_Timer_Action is record
      Send_Keepalive  : Interfaces.Unsigned_8;
      Initiate_Rekey  : Interfaces.Unsigned_8;
      Session_Expired : Interfaces.Unsigned_8;
      Rekey_Timed_Out : Interfaces.Unsigned_8;
   end record
   with Convention => C;

   type C_Action_Array is
     array (0 .. Session.Max_Peers - 1) of C_Timer_Action
   with Convention => C;

   procedure C_Session_Tick_All
     (Now     : Interfaces.Unsigned_64;
      Actions : out C_Action_Array)
   with Export,
        Convention    => C,
        External_Name => "session_tick_all",
        SPARK_Mode    => Off;
   --  Evaluate all peer timers under a single lock hold.
   --  Fills Actions[0..Max_Peers-1].  C index 0 = Peer 1.

   ---------------------------------------------------------------------------
   --  Timer action dispatch — called by WG task (pri 6)
   ---------------------------------------------------------------------------

   procedure C_Session_Expire
     (Peer : Interfaces.C.unsigned)
   with Export,
        Convention    => C,
        External_Name => "session_expire",
        SPARK_Mode    => Off;
   --  Wipe all keypair slots.  Session_Expired / Rekey_Timed_Out.

   procedure C_Session_Set_Rekey_Flag
     (Peer : Interfaces.C.unsigned;
      Now  : Interfaces.Unsigned_64)
   with Export,
        Convention    => C,
        External_Name => "session_set_rekey_flag",
        SPARK_Mode    => Off;
   --  Mark rekey in progress before sending initiation.

end WG_Sessions;
