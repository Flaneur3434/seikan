--  VeriGuard Test Suite
--
--  This package provides a simple test framework for unit and property testing.
--  Tests can be registered and run via the Test_Runner.

package Tests is

   type Test_Result is (Pass, Fail, Skip);

   type Test_Count is record
      Passed  : Natural := 0;
      Failed  : Natural := 0;
      Skipped : Natural := 0;
   end record;

   --  Assert that a condition is true
   procedure Assert (Condition : Boolean; Message : String := "");

   --  Assert that two values are equal
   generic
      type T is private;
      with function "=" (Left, Right : T) return Boolean is <>;
      with function Image (Value : T) return String;
   procedure Assert_Equal (Expected, Actual : T; Message : String := "");

   --  Report test results
   procedure Report_Results (Results : Test_Count);

end Tests;
