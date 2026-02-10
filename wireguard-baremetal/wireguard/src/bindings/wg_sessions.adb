--  WG_Sessions - C FFI Implementation

with Session;

package body WG_Sessions
   with SPARK_Mode => Off
is

   procedure C_Session_Init (Sem : not null Threads.Mutex.Semaphore_Ref) is
   begin
      Session.Init (Sem);
   end C_Session_Init;

end WG_Sessions;
