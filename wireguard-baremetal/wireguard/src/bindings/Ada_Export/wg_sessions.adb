--  WG_Sessions - C FFI Implementation

with Session.Timers;
with Timer.Clock;

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
   --  Single-peer timer evaluation
   ---------------------------------------------------------------------------

   procedure C_Session_On_Peer_Timer_Due
     (Peer                 : Interfaces.C.unsigned;
      Now                  : Interfaces.Unsigned_64;
      Out_Action           : access Interfaces.Unsigned_8;
      Out_Next_Deadline_Ms : access Interfaces.Unsigned_64)
   is
      Action   : Session.Timers.Timer_Action;
      Deadline : Timer.Clock.Timestamp;
   begin
      if Out_Action = null or else Out_Next_Deadline_Ms = null then
         return;
      end if;

      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         Out_Action.all           := 0;
         Out_Next_Deadline_Ms.all := 0;
         return;
      end if;

      Session.Timers.On_Peer_Timer_Due
        (Peer_Idx      => Session.Peer_Index (Peer),
         Now           => Now,
         Action        => Action,
         Next_Deadline => Deadline);

      Out_Action.all :=
        Interfaces.Unsigned_8 (Session.Timers.Timer_Action'Pos (Action));
      Out_Next_Deadline_Ms.all := Interfaces.Unsigned_64 (Deadline);
   end C_Session_On_Peer_Timer_Due;

   ---------------------------------------------------------------------------
   --  Single-peer next-deadline query
   ---------------------------------------------------------------------------

   procedure C_Session_Next_Deadline
     (Peer                 : Interfaces.C.unsigned;
      Now                  : Interfaces.Unsigned_64;
      Out_Next_Deadline_Ms : access Interfaces.Unsigned_64)
   is
      Deadline : Timer.Clock.Timestamp;
   begin
      if Out_Next_Deadline_Ms = null then
         return;
      end if;

      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         Out_Next_Deadline_Ms.all := 0;
         return;
      end if;

      Session.Timers.Locked_Next_Deadline
        (Peer_Idx      => Session.Peer_Index (Peer),
         Now           => Now,
         Next_Deadline => Deadline);

      Out_Next_Deadline_Ms.all := Interfaces.Unsigned_64 (Deadline);
   end C_Session_Next_Deadline;

   ---------------------------------------------------------------------------
   --  Session query
   ---------------------------------------------------------------------------

   function C_Session_Is_Active
     (Peer : Interfaces.C.unsigned)
      return Interfaces.C.unsigned_char
   is
      KP : Session.Keypair;
   begin
      if Peer not in
        Interfaces.C.unsigned (Session.Peer_Index'First) ..
        Interfaces.C.unsigned (Session.Peer_Index'Last)
      then
         return 0;
      end if;

      Session.Get_Current (Session.Peer_Index (Peer), KP);

      if Session.Is_Valid (KP) then
         return 1;
      else
         return 0;
      end if;
   end C_Session_Is_Active;

end WG_Sessions;
