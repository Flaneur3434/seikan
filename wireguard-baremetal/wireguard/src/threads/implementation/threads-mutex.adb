--  Threads.Mutex - Implementation delegating to platform backend

with Threads.Platform;

package body Threads.Mutex
  with SPARK_Mode => Off
is

   procedure Init_From_Handle
     (M   : out Mutex_Handle;
      Sem : not null Semaphore_Ref)
   is
   begin
      M.Sem := Sem;
   end Init_From_Handle;

   function Is_Initialized (M : Mutex_Handle) return Boolean is
   begin
      return M.Sem /= null;
   end Is_Initialized;

   procedure Lock (M : in out Mutex_Handle) is
   begin
      Threads.Platform.Mutex_Lock (M.Sem);
   end Lock;

   procedure Unlock (M : in out Mutex_Handle) is
   begin
      Threads.Platform.Mutex_Unlock (M.Sem);
   end Unlock;

end Threads.Mutex;
