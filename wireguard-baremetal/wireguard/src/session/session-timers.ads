package Session.Timers
  with SPARK_Mode => On
is
   --  State transitions of the session state machine
   type Primary_Action is
     (Primary_None,
      Primary_Initiate_Rekey,
      Primary_Rekey_Timed_Out,
      Primary_Session_Expired,
      Primary_Rekey_Success,
      Primary_Activate_Next);

   --  Effects represent orthogonal actions that can arise along side the main
   --  state machine
   type Effect_Action is (Effect_Send_Keepalive);

   type Effects_Set is array (Effect_Action) of Boolean with Pack;

   type Timer_Action is record
      Primary : Primary_Action := Primary_None;
      Effects : Effects_Set := (others => False);
   end record
   with
     --  Session Expired states takes precedence over everything else
     Predicate =>
       (if Primary = Primary_Session_Expired
        then (for all E in Effect_Action => not Effects (E))
        else True);

   function Tick
     (Peer_Idx : Peer_Index; Now : Timer.Clock.Timestamp) return Timer_Action
   with Pre => Now > Timer.Clock.Never;

   type Timer_Actions is array (Peer_Index) of Timer_Action;

   procedure Tick_All
     (Now : Timer.Clock.Timestamp; Actions : out Timer_Actions)
   with
     Gloabl => (In_Out => (Peer_States, Mtx)),
     Pre    =>
       Is_Mtx_Initialized
       and then not Is_Mtx_Locked
       and then Now > Timer.Clock.Never;
end Session.Timers;
