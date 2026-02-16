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

   ---------------------------------------------------------------------------
   --  Timer action dispatch — called by WG task (pri 6)
   ---------------------------------------------------------------------------

   --  Wipe all keypair slots.  Session_Expired / Rekey_Timed_Out.
   procedure C_Session_Expire
     (Peer : Interfaces.C.unsigned)
   with Export,
        Convention    => C,
        External_Name => "session_expire",
        SPARK_Mode    => Off;

   --  Mark rekey in progress before sending initiation.
   procedure C_Session_Set_Rekey_Flag
     (Peer : Interfaces.C.unsigned;
      Now  : Interfaces.Unsigned_64)
   with Export,
        Convention    => C,
        External_Name => "session_set_rekey_flag",
        SPARK_Mode    => Off;

end WG_Sessions;
