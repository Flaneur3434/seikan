--  Threads.Platform - POSIX pthreads backend for host builds
--
--  This is a PRIVATE package - only visible within Threads hierarchy.
--  Provides OS-level lock/unlock via POSIX pthreads.
--
--  Mutex creation is done by the caller (C side or test harness).
--  The handle (pthread_mutex_t*) is passed into Ada via Init_From_Handle.

with Threads.Mutex;

private package Threads.Platform
  with SPARK_Mode => Off
is

   --  Acquire mutex, blocking until available.
   procedure Mutex_Lock (Sem : not null Threads.Mutex.Semaphore_Ref);

   --  Release mutex.
   procedure Mutex_Unlock (Sem : not null Threads.Mutex.Semaphore_Ref);

end Threads.Platform;
