--  WG_Sessions - C FFI for session table initialization
--
--  Provides C-callable interface so C can create the binary semaphore
--  (static allocation, zero heap) and hand the handle into Ada.
--
--  Call chain:
--    C: wg_session_init()  →  Ada: session_init(sem)  →  Session.Init(sem)

with Threads.Mutex;

package WG_Sessions
   with SPARK_Mode => On
is

   procedure C_Session_Init (Sem : not null Threads.Mutex.Semaphore_Ref)
     with Export,
          Convention    => C,
          External_Name => "session_init",
          SPARK_Mode    => Off;
   --  Called from wg_sessions.c after creating the binary semaphore.
   --  Initializes the session table and stores the mutex handle.

end WG_Sessions;
