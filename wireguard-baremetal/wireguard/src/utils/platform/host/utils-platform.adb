--  Utils.Platform - Host/Linux Implementation
--
--  Implements platform primitives using POSIX pthreads:
--    - pthread_mutex / pthread_cond for queue operations
--    - pthread_mutex for critical sections
--    - usleep / clock_gettime for timing
--
--  This implementation is for host testing on Linux/macOS.

with System;
with Interfaces.C;
with Ada.Unchecked_Deallocation;

package body Utils.Platform
  with SPARK_Mode => Off
is
   use Interfaces.C;

   ---------------------
   --  POSIX Imports
   ---------------------

   --  pthread_mutex_t and pthread_cond_t are opaque types
   --  We'll use a fixed-size buffer that's large enough
   Mutex_Size : constant := 64;  --  Enough for pthread_mutex_t
   Cond_Size  : constant := 64;  --  Enough for pthread_cond_t

   type Mutex_Buffer is array (1 .. Mutex_Size) of unsigned_char;
   type Cond_Buffer is array (1 .. Cond_Size) of unsigned_char;

   function pthread_mutex_init
     (Mutex : System.Address;
      Attr  : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_mutex_init";

   function pthread_mutex_destroy (Mutex : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_mutex_destroy";

   function pthread_mutex_lock (Mutex : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_mutex_lock";

   function pthread_mutex_unlock (Mutex : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_mutex_unlock";

   function pthread_cond_init
     (Cond : System.Address;
      Attr : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_cond_init";

   function pthread_cond_destroy (Cond : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_cond_destroy";

   function pthread_cond_signal (Cond : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_cond_signal";

   function pthread_cond_wait
     (Cond  : System.Address;
      Mutex : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_cond_wait";

   --  timespec structure for timed wait
   type Timespec is record
      Tv_Sec  : long;
      Tv_Nsec : long;
   end record with Convention => C;

   function pthread_cond_timedwait
     (Cond    : System.Address;
      Mutex   : System.Address;
      Abstime : System.Address) return int
   with Import, Convention => C, External_Name => "pthread_cond_timedwait";

   --  Time functions
   CLOCK_MONOTONIC : constant := 1;

   function clock_gettime
     (Clock_Id : int;
      Tp       : System.Address) return int
   with Import, Convention => C, External_Name => "clock_gettime";

   function usleep (Usec : unsigned) return int
   with Import, Convention => C, External_Name => "usleep";

   --  ETIMEDOUT for pthread_cond_timedwait
   ETIMEDOUT : constant := 110;  --  Linux value

   ---------------------
   --  Queue Implementation
   ---------------------

   --  A simple bounded queue using circular buffer
   type Descriptor_Array is array (Natural range <>)
      of aliased Buffer_Descriptor;

   type Queue_Data (Capacity : Positive) is record
      Mutex     : aliased Mutex_Buffer;
      Not_Empty : aliased Cond_Buffer;
      Not_Full  : aliased Cond_Buffer;
      Items     : Descriptor_Array (0 .. Capacity - 1);
      Head      : Natural := 0;
      Tail      : Natural := 0;
      Count     : Natural := 0;
   end record;

   type Queue_Data_Access is access Queue_Data;

   procedure Free_Queue is new Ada.Unchecked_Deallocation
     (Queue_Data, Queue_Data_Access);

   ---------------------
   --  Helper Functions
   ---------------------

   function To_Queue (H : Queue_Handle) return Queue_Data_Access is
   begin
      return Queue_Data_Access
        (System.Address'Deref (System.Address (H)'Unrestricted_Access));
   end To_Queue;

   pragma Warnings (Off, "possible aliasing problem*");

   function Get_Absolute_Time (Timeout_Ms : Natural) return Timespec is
      Now    : aliased Timespec;
      Result : int;
      pragma Unreferenced (Result);
   begin
      Result := clock_gettime (CLOCK_MONOTONIC, Now'Address);

      if Timeout_Ms = Natural'Last then
         --  Very far in future (effectively infinite)
         return (Tv_Sec => long'Last / 2, Tv_Nsec => 0);
      end if;

      --  Add timeout to current time
      declare
         Add_Sec  : constant long := long (Timeout_Ms / 1000);
         Add_Nsec : constant long := long ((Timeout_Ms mod 1000) * 1_000_000);
         New_Nsec : long := Now.Tv_Nsec + Add_Nsec;
         New_Sec  : long := Now.Tv_Sec + Add_Sec;
      begin
         if New_Nsec >= 1_000_000_000 then
            New_Sec := New_Sec + 1;
            New_Nsec := New_Nsec - 1_000_000_000;
         end if;
         return (Tv_Sec => New_Sec, Tv_Nsec => New_Nsec);
      end;
   end Get_Absolute_Time;

   ---------------------
   --  Queue Operations
   ---------------------

   function Queue_Create (Depth : Positive := Default_Queue_Depth)
      return Queue_Handle
   is
      Q      : Queue_Data_Access;
      Result : int;
      pragma Unreferenced (Result);
   begin
      Q := new Queue_Data (Capacity => Depth);

      Result := pthread_mutex_init (Q.Mutex'Address, System.Null_Address);
      Result := pthread_cond_init (Q.Not_Empty'Address, System.Null_Address);
      Result := pthread_cond_init (Q.Not_Full'Address, System.Null_Address);

      return Queue_Handle (Q.all'Address);
   end Queue_Create;

   procedure Queue_Delete (Queue : in out Queue_Handle) is
      Q      : Queue_Data_Access;
      Result : int;
      pragma Unreferenced (Result);
   begin
      if Queue = Null_Queue then
         return;
      end if;

      Q := To_Queue (Queue);
      Result := pthread_cond_destroy (Q.Not_Full'Address);
      Result := pthread_cond_destroy (Q.Not_Empty'Address);
      Result := pthread_mutex_destroy (Q.Mutex'Address);
      Free_Queue (Q);
      Queue := Null_Queue;
   end Queue_Delete;

   function Queue_Is_Valid (Queue : Queue_Handle) return Boolean is
   begin
      return Queue /= Null_Queue;
   end Queue_Is_Valid;

   function Queue_Send
     (Queue      : Queue_Handle;
      Descriptor : Buffer_Descriptor;
      Timeout_Ms : Natural := 0) return Boolean
   is
      Q       : constant Queue_Data_Access := To_Queue (Queue);
      Result  : int;
      Abstime : aliased Timespec;
      pragma Unreferenced (Result);
   begin
      Result := pthread_mutex_lock (Q.Mutex'Address);

      --  Wait for space if queue is full
      while Q.Count >= Q.Capacity loop
         if Timeout_Ms = 0 then
            Result := pthread_mutex_unlock (Q.Mutex'Address);
            return False;  --  No wait, queue full
         end if;

         Abstime := Get_Absolute_Time (Timeout_Ms);
         Result := pthread_cond_timedwait
           (Q.Not_Full'Address, Q.Mutex'Address, Abstime'Address);

         if Result = ETIMEDOUT then
            Result := pthread_mutex_unlock (Q.Mutex'Address);
            return False;
         end if;
      end loop;

      --  Enqueue the descriptor
      Q.Items (Q.Tail) := Descriptor;
      Q.Tail := (Q.Tail + 1) mod Q.Capacity;
      Q.Count := Q.Count + 1;

      Result := pthread_cond_signal (Q.Not_Empty'Address);
      Result := pthread_mutex_unlock (Q.Mutex'Address);

      return True;
   end Queue_Send;

   function Queue_Receive
     (Queue      : Queue_Handle;
      Descriptor : out Buffer_Descriptor;
      Timeout_Ms : Natural := Natural'Last) return Boolean
   is
      Q       : constant Queue_Data_Access := To_Queue (Queue);
      Result  : int;
      Abstime : aliased Timespec;
      pragma Unreferenced (Result);
   begin
      Result := pthread_mutex_lock (Q.Mutex'Address);

      --  Wait for item if queue is empty
      while Q.Count = 0 loop
         if Timeout_Ms = 0 then
            Descriptor := Null_Buffer;
            Result := pthread_mutex_unlock (Q.Mutex'Address);
            return False;  --  No wait, queue empty
         end if;

         Abstime := Get_Absolute_Time (Timeout_Ms);
         Result := pthread_cond_timedwait
           (Q.Not_Empty'Address, Q.Mutex'Address, Abstime'Address);

         if Result = ETIMEDOUT then
            Descriptor := Null_Buffer;
            Result := pthread_mutex_unlock (Q.Mutex'Address);
            return False;
         end if;
      end loop;

      --  Dequeue the descriptor
      Descriptor := Q.Items (Q.Head);
      Q.Head := (Q.Head + 1) mod Q.Capacity;
      Q.Count := Q.Count - 1;

      Result := pthread_cond_signal (Q.Not_Full'Address);
      Result := pthread_mutex_unlock (Q.Mutex'Address);

      return True;
   end Queue_Receive;

   function Queue_Count (Queue : Queue_Handle) return Natural is
      Q      : constant Queue_Data_Access := To_Queue (Queue);
      Result : int;
      Count  : Natural;
      pragma Unreferenced (Result);
   begin
      Result := pthread_mutex_lock (Q.Mutex'Address);
      Count := Q.Count;
      Result := pthread_mutex_unlock (Q.Mutex'Address);
      return Count;
   end Queue_Count;

   function Queue_Is_Empty (Queue : Queue_Handle) return Boolean is
   begin
      return Queue_Count (Queue) = 0;
   end Queue_Is_Empty;

   function Queue_Is_Full (Queue : Queue_Handle) return Boolean is
      Q : constant Queue_Data_Access := To_Queue (Queue);
   begin
      return Queue_Count (Queue) >= Q.Capacity;
   end Queue_Is_Full;

   ---------------------
   --  Critical Sections
   ---------------------

   Critical_Mutex : aliased Mutex_Buffer;
   Critical_Init  : Boolean := False;

   procedure Enter_Critical is
      Result : int;
      pragma Unreferenced (Result);
   begin
      if not Critical_Init then
         Result := pthread_mutex_init
           (Critical_Mutex'Address, System.Null_Address);
         Critical_Init := True;
      end if;
      Result := pthread_mutex_lock (Critical_Mutex'Address);
   end Enter_Critical;

   procedure Exit_Critical is
      Result : int;
      pragma Unreferenced (Result);
   begin
      Result := pthread_mutex_unlock (Critical_Mutex'Address);
   end Exit_Critical;

   ---------------------
   --  Time Operations
   ---------------------

   procedure Delay_Ms (Ms : Natural) is
      Result : int;
      pragma Unreferenced (Result);
   begin
      Result := usleep (unsigned (Ms) * 1000);
   end Delay_Ms;

   function Get_Time_Ms return Unsigned_32 is
      Now    : aliased Timespec;
      Result : int;
      pragma Unreferenced (Result);
   begin
      Result := clock_gettime (CLOCK_MONOTONIC, Now'Address);
      return Unsigned_32 (Now.Tv_Sec) * 1000 +
             Unsigned_32 (Now.Tv_Nsec / 1_000_000);
   end Get_Time_Ms;

end Utils.Platform;
