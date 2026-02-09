--  Threads.Platform - POSIX pthreads implementation

with Ada.Unchecked_Conversion;
with System;
with Interfaces.C; use Interfaces.C;

package body Threads.Platform
  with SPARK_Mode => Off
is
   --  POSIX pthreads (take raw Address for C interop)
   function Pthread_Mutex_Lock (Mutex : System.Address) return int
     with Import, Convention => C, External_Name => "pthread_mutex_lock";

   function Pthread_Mutex_Unlock (Mutex : System.Address) return int
     with Import, Convention => C, External_Name => "pthread_mutex_unlock";

   --  Convert Semaphore_Ref (access type) to System.Address for the C calls
   function To_Address is new Ada.Unchecked_Conversion
     (Threads.Mutex.Semaphore_Ref, System.Address);

   ---------------------------------------------------------------------------

   procedure Mutex_Lock (Sem : not null Threads.Mutex.Semaphore_Ref) is
      Ret : int;
      pragma Unreferenced (Ret);
   begin
      Ret := Pthread_Mutex_Lock (To_Address (Sem));
   end Mutex_Lock;

   procedure Mutex_Unlock (Sem : not null Threads.Mutex.Semaphore_Ref) is
      Ret : int;
      pragma Unreferenced (Ret);
   begin
      Ret := Pthread_Mutex_Unlock (To_Address (Sem));
   end Mutex_Unlock;

end Threads.Platform;
