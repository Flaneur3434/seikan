--  Threads.Mutex - Platform-independent mutex interface
--
--  Provides a simple mutual exclusion primitive for protecting shared
--  data structures accessed from multiple threads/tasks.
--
--  The caller owns semaphore/mutex creation (C side) and passes the
--  opaque handle to Ada via Init_From_Handle.
--
--  Usage:
--    M : Mutex_Handle;
--    ...
--    Init_From_Handle (M, Sem_Ptr);
--    Lock (M);
--    --  critical section
--    Unlock (M);
--
--  The underlying lock/unlock is selected at build time:
--    esp_idf → FreeRTOS xSemaphoreTake / xSemaphoreGive  (via C wrappers)
--    host    → POSIX pthread_mutex_lock / unlock

package Threads.Mutex
  with SPARK_Mode => On
is
   ---------------------------------------------------------------------------
   --  OS Semaphore Handle
   --
   --  Opaque access type representing an OS-level lock object.
   --  On FreeRTOS this is SemaphoreHandle_t; on POSIX it is
   --  pthread_mutex_t*.  Ada never dereferences it — it is only
   --  passed through to the platform lock/unlock C functions.
   ---------------------------------------------------------------------------

   type OS_Semaphore is limited private;
   type Semaphore_Ref is access all OS_Semaphore
     with Convention => C;

   ---------------------------------------------------------------------------
   --  Mutex Handle
   ---------------------------------------------------------------------------

   type Mutex_Handle is limited private;

   ---------------------------------------------------------------------------
   --  Operations
   ---------------------------------------------------------------------------

   procedure Init_From_Handle
     (M   : out Mutex_Handle;
      Sem : not null Semaphore_Ref)
     with Global => null,
          Post   => Is_Initialized (M) and then not Is_Locked (M);
   --  Store a pre-created OS lock handle.
   --  Function is only valid before multiple threads start contesting for lock

   function Is_Initialized (M : Mutex_Handle) return Boolean
     with Global => null;
   --  True if Init_From_Handle has been called with a non-null handle.

   function Is_Locked (M : Mutex_Handle) return Boolean
     with Ghost,
          Global => null;
   --  True while the mutex is held (between Lock and Unlock).

   procedure Lock (M : in out Mutex_Handle)
     with Global => null,
          Pre    => Is_Initialized (M),
          Post   => Is_Initialized (M) and Is_Locked (M);

   procedure Unlock (M : in out Mutex_Handle)
     with Global => null,
          Pre    => Is_Initialized (M),
          Post   => Is_Initialized (M) and not Is_Locked (M);

private

   type OS_Semaphore is limited null record;

   type Mutex_Handle is limited record
      Sem    : Semaphore_Ref := null;
      Locked : Boolean       := False;
   end record;

end Threads.Mutex;
