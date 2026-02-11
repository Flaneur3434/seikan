--  WG_Sessions - C FFI Implementation

with Session.Timers;

package body WG_Sessions
   with SPARK_Mode => Off
is

   --  Boolean → Unsigned_8 for C struct (0 = false, 1 = true)
   function B2U (V : Boolean) return Interfaces.Unsigned_8 is
     (if V then 1 else 0);

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
         declare
            A : Session.Timers.Timer_Action renames
              Ada_Actions (I);
         begin
            Actions (Integer (I) - 1) :=
              (Send_Keepalive  => B2U (A.Send_Keepalive),
               Initiate_Rekey  => B2U (A.Initiate_Rekey),
               Session_Expired => B2U (A.Session_Expired),
               Rekey_Timed_Out => B2U (A.Rekey_Timed_Out));
         end;
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
