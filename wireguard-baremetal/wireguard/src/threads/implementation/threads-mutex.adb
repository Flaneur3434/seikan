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
      M.Sem    := Sem;
      M.Locked := False;
   end Init_From_Handle;

   function Is_Initialized (M : Mutex_Handle) return Boolean is
   begin
      return M.Sem /= null;
   end Is_Initialized;

   function Is_Locked (M : Mutex_Handle) return Boolean is
   begin
      return M.Locked;
   end Is_Locked;

   procedure Lock (M : in out Mutex_Handle) is
   begin
      Threads.Platform.Mutex_Lock (M.Sem);
      M.Locked := True;
   end Lock;

   procedure Unlock (M : in out Mutex_Handle) is
   begin
      Threads.Platform.Mutex_Unlock (M.Sem);
      M.Locked := False;
   end Unlock;

end Threads.Mutex;
