--  Session.Timer - Implementation

with Session.Timers;
package body Session.Timers
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Elapsed — Compute seconds elapsed since a timestamp
   ---------------------------------------------------------------------------

   function Elapsed
     (Start : Timer.Clock.Timestamp;
      Now   : Timer.Clock.Timestamp) return Unsigned_64
   is
   begin
      if Now < Start then
         return 0;
      end if;
      return Now - Start;
   end Elapsed;

   ---------------------------------------------------------------------------
   --  Tick — Evaluate one peer's timer conditions
   ---------------------------------------------------------------------------

   function Tick
     (Peer_Idx : Peer_Index;
      Now  : Timer.Clock.Timestamp) return Timer_Action
   is
      Peer : Peer_State := Peers (Peer_Idx);
   begin
   end Tick;

   ---------------------------------------------------------------------------
   --  Tick_All — Scan every active peer
   ---------------------------------------------------------------------------

   procedure Tick_All
     (Now     : Timer.Clock.Timestamp;
      Actions : out Timer_Actions)
   is
   begin
      Lock;
      for I in Peer_Index loop
         Actions (I) := Tick (I, Now);
      end loop;
      Unlock;
   end Tick_All;

end Session.Timers;
