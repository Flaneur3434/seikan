--  WG_Sessions - C FFI Implementation

with Session.Timers;

package body WG_Sessions
   with SPARK_Mode => Off
is

   ---------------------------------------------------------------------------
   --  Initialization
   ---------------------------------------------------------------------------

   procedure C_Session_Init
     (Sem : not null Threads.Mutex.Semaphore_Ref) is
   begin
      Session.Init (Sem);
   end C_Session_Init;

   ---------------------------------------------------------------------------
   --  Timer tick
   ---------------------------------------------------------------------------

   procedure C_Session_Tick_All
     (Now     : Interfaces.Unsigned_64;
      Actions : out C_Action_Array)
   is
      Ada_Actions : Session.Timers.Action_Array;
   begin
      Session.Timers.Tick_All (Now, Ada_Actions);
      for I in Session.Peer_Index loop
         Actions (I - 1) :=
           Session.Timers.Timer_Action'Pos (Ada_Actions (I));
      end loop;
   end C_Session_Tick_All;

   ---------------------------------------------------------------------------
   --  Timer action dispatch
   ---------------------------------------------------------------------------

   procedure C_Session_Expire
     (Peer : Interfaces.C.unsigned) is
   begin
      if Peer in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         Session.Expire_Session (Session.Peer_Index (Peer));
      end if;
   end C_Session_Expire;

   procedure C_Session_Set_Rekey_Flag
     (Peer : Interfaces.C.unsigned;
      Now  : Interfaces.Unsigned_64) is
   begin
      if Peer in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         Session.Set_Rekey_Flag
           (Session.Peer_Index (Peer), Now);
      end if;
   end C_Session_Set_Rekey_Flag;

end WG_Sessions;
