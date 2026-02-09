--  Threads.Platform - FreeRTOS backend for ESP-IDF
--
--  This is a PRIVATE package - only visible within Threads hierarchy.
--  Provides OS-level lock/unlock via FreeRTOS binary semaphore API.
--
--  We use binary semaphores (not mutexes) because the critical sections
--  are tiny and we don't need priority-inheritance overhead.
--
--  Semaphore creation is done in C (packet_pool.c) using static
--  allocation. The handle is passed into Ada via Init_From_Handle.
--
--  FreeRTOS xSemaphoreTake / xSemaphoreGive are macros, so we use
--  thin C wrappers (src/bindings/wg_mutex.c) for real function symbols.

with Threads.Mutex;

private package Threads.Platform
  with SPARK_Mode => Off
is

   --  Acquire lock, blocking indefinitely (portMAX_DELAY).
   procedure Mutex_Lock (Sem : not null Threads.Mutex.Semaphore_Ref)
     with Import, Convention => C,
          External_Name => "wg_mutex_lock";

   --  Release lock.
   procedure Mutex_Unlock (Sem : not null Threads.Mutex.Semaphore_Ref)
     with Import, Convention => C,
          External_Name => "wg_mutex_unlock";

end Threads.Platform;
