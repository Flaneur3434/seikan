--  VeriGuard Test Suite Implementation

with Ada.Text_IO; use Ada.Text_IO;

package body Tests is

   procedure Assert (Condition : Boolean; Message : String := "") is
   begin
      if not Condition then
         if Message'Length > 0 then
            raise Program_Error with "Assertion failed: " & Message;
         else
            raise Program_Error with "Assertion failed";
         end if;
      end if;
   end Assert;

   procedure Assert_Equal (Expected, Actual : T; Message : String := "") is
   begin
      if Expected /= Actual then
         declare
            Msg : constant String :=
              "Expected: " & Image (Expected) & ", Got: " & Image (Actual);
         begin
            if Message'Length > 0 then
               raise Program_Error with Message & " - " & Msg;
            else
               raise Program_Error with Msg;
            end if;
         end;
      end if;
   end Assert_Equal;

   procedure Report_Results (Results : Test_Count) is
      Total : constant Natural :=
        Results.Passed + Results.Failed + Results.Skipped;
   begin
      New_Line;
      Put_Line ("========================================");
      Put_Line ("Test Results:");
      Put_Line ("========================================");
      Put_Line ("  Total:   " & Natural'Image (Total));
      Put_Line ("  Passed:  " & Natural'Image (Results.Passed));
      Put_Line ("  Failed:  " & Natural'Image (Results.Failed));
      Put_Line ("  Skipped: " & Natural'Image (Results.Skipped));
      Put_Line ("========================================");

      if Results.Failed > 0 then
         Put_Line ("FAILURE");
      else
         Put_Line ("SUCCESS");
      end if;
   end Report_Results;

end Tests;
