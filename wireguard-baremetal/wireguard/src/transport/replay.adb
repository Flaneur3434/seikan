--  Replay -- Lightweight 64-bit bitmap anti-replay filter
--
--  Three cases for incoming counter C against highest H:
--    C > H        -> new packet, slide window forward
--    H-63 <= C <= H -> within window, check/set bitmap bit
--    C < H-63     -> too old, reject

package body Replay
  with SPARK_Mode => On
is

   procedure Reset (F : out Filter) is
   begin
      F.Last   := 0;
      F.Bitmap := 0;
   end Reset;

   procedure Validate_Counter
     (F        : in out Filter;
      Counter  : Unsigned_64;
      Limit    : Unsigned_64;
      Accepted : out Boolean)
   is
      Shift  : Unsigned_64;
      Offset : Natural;
      Mask   : Unsigned_64;
   begin
      --  Reject over-limit counters
      if Counter >= Limit then
         Accepted := False;
         return;
      end if;

      --  Case 1: Packet is newer than any seen
      if Counter > F.Last then
         Shift := Counter - F.Last;

         if Shift >= Window_Size then
            --  Entire old window is obsolete
            F.Bitmap := 1;
         else
            F.Bitmap :=
              Shift_Left (F.Bitmap, Natural (Shift)) or 1;
         end if;

         F.Last   := Counter;
         Accepted := True;
         return;
      end if;

      --  Case 3: Packet too old  (C <= H - 64)
      if F.Last - Counter >= Window_Size then
         Accepted := False;
         return;
      end if;

      --  Case 2: Packet within the window
      Offset := Natural (F.Last - Counter);
      Mask   := Shift_Left (Unsigned_64'(1), Offset);

      if (F.Bitmap and Mask) /= 0 then
         Accepted := False;   --  duplicate
      else
         F.Bitmap := F.Bitmap or Mask;
         Accepted := True;
      end if;
   end Validate_Counter;

end Replay;
