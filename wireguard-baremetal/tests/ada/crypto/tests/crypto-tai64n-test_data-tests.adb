--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.TAI64N.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

--  begin read only
--  end read only
package body Crypto.TAI64N.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

   use Interfaces;

--  begin read only
--  end read only

--  begin read only
   procedure Test_Now (Gnattest_T : in out Test);
   procedure Test_Now_268a09 (Gnattest_T : in out Test) renames Test_Now;
--  id:2.2/268a0928f3ca5dbd/Now/1/0/
   procedure Test_Now (Gnattest_T : in out Test) is
   --  crypto-tai64n.ads:29:4:Now
--  end read only

      pragma Unreferenced (Gnattest_T);

      T1, T2, T3 : Timestamp;
   begin
      --  Test 1: Now returns non-zero timestamp
      Now (T1);
      Assert (T1 /= Zero, "Now should return non-zero timestamp");

      --  Test 2: Successive calls are strictly increasing
      Now (T2);
      Assert (Is_After (T2, T1), "Second timestamp should be after first");

      --  Test 3: Third call also strictly increasing
      Now (T3);
      Assert (Is_After (T3, T2), "Third timestamp should be after second");
      Assert (Is_After (T3, T1), "Third timestamp should be after first");

--  begin read only
   end Test_Now;
--  end read only


--  begin read only
   procedure Test_Is_After (Gnattest_T : in out Test);
   procedure Test_Is_After_79f668 (Gnattest_T : in out Test) renames Test_Is_After;
--  id:2.2/79f668f77949a29c/Is_After/1/0/
   procedure Test_Is_After (Gnattest_T : in out Test) is
   --  crypto-tai64n.ads:35:4:Is_After
--  end read only

      pragma Unreferenced (Gnattest_T);

      A, B : Timestamp;
   begin
      --  Test 1: Zero is not after Zero
      Assert (not Is_After (Zero, Zero), "Zero should not be after Zero");

      --  Test 2: Non-zero is after Zero
      Now (A);
      Assert (Is_After (A, Zero), "Non-zero should be after Zero");

      --  Test 3: Zero is not after non-zero
      Assert (not Is_After (Zero, A), "Zero should not be after non-zero");

      --  Test 4: Earlier not after later
      Now (B);
      Assert (not Is_After (A, B), "Earlier should not be after later");

      --  Test 5: Later is after earlier
      Assert (Is_After (B, A), "Later should be after earlier");

--  begin read only
   end Test_Is_After;
--  end read only


--  begin read only
   procedure Test_Is_After_Or_Equal (Gnattest_T : in out Test);
   procedure Test_Is_After_Or_Equal_eb2c5b (Gnattest_T : in out Test) renames Test_Is_After_Or_Equal;
--  id:2.2/eb2c5b4217c74bce/Is_After_Or_Equal/1/0/
   procedure Test_Is_After_Or_Equal (Gnattest_T : in out Test) is
   --  crypto-tai64n.ads:39:4:Is_After_Or_Equal
--  end read only

      pragma Unreferenced (Gnattest_T);

      A, B : Timestamp;
   begin
      --  Test 1: Zero is equal to Zero
      Assert (Is_After_Or_Equal (Zero, Zero), "Zero should be >= Zero");

      --  Test 2: Non-zero is after or equal to Zero
      Now (A);
      Assert (Is_After_Or_Equal (A, Zero), "Non-zero should be >= Zero");

      --  Test 3: Zero is not after or equal to non-zero
      Assert (not Is_After_Or_Equal (Zero, A), "Zero should not be >= non-zero");

      --  Test 4: Same value is after or equal to itself
      Assert (Is_After_Or_Equal (A, A), "Timestamp should be >= itself");

      --  Test 5: Later is after or equal to earlier
      Now (B);
      Assert (Is_After_Or_Equal (B, A), "Later should be >= earlier");

      --  Test 6: Earlier is not after or equal to later
      Assert (not Is_After_Or_Equal (A, B), "Earlier should not be >= later");

--  begin read only
   end Test_Is_After_Or_Equal;
--  end read only

--  begin read only
--  id:2.2/02/
--
--  This section can be used to add elaboration code for the global state.
--
begin
--  end read only
   null;
--  begin read only
--  end read only
end Crypto.TAI64N.Test_Data.Tests;
