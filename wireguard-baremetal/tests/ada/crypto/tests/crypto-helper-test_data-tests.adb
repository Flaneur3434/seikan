--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.Helper.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Interfaces; use Interfaces;

--  begin read only
--  end read only
package body Crypto.Helper.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

   use Utils;  --  For From_Array and Byte_Span operations

--  begin read only
--  end read only

--  begin read only
   procedure Test_Memzero (Gnattest_T : in out Test);
   procedure Test_Memzero_001f23 (Gnattest_T : in out Test) renames Test_Memzero;
--  id:2.2/001f23d595ac0183/Memzero/1/0/
   procedure Test_Memzero (Gnattest_T : in out Test) is
   --  crypto-helper.ads:12:4:Memzero
--  end read only

      pragma Unreferenced (Gnattest_T);

      Buffer : aliased Byte_Array (0 .. 31) := (others => 16#FF#);

   begin
      --  Test 1: Memzero should zero out a buffer filled with 0xFF
      Memzero (Buffer);

      declare
         All_Zeros : Boolean := True;
      begin
         for I in Buffer'Range loop
            if Buffer (I) /= 0 then
               All_Zeros := False;
               exit;
            end if;
         end loop;
         Assert (All_Zeros, "Memzero should set all bytes to zero");
      end;

      --  Test 2: Memzero on already-zero buffer should still be zero
      Memzero (Buffer);
      Assert (Buffer = (Buffer'Range => 0),
              "Memzero on zero buffer should remain zero");

      --  Test 3: Memzero with pattern data
      for I in Buffer'Range loop
         Buffer (I) := Unsigned_8 (Integer (I) mod 256);
      end loop;

      Memzero (Buffer);
      Assert (Buffer = (Buffer'Range => 0),
              "Memzero should zero pattern-filled buffer");

--  begin read only
   end Test_Memzero;
--  end read only


--  begin read only
   procedure Test_Cmp (Gnattest_T : in out Test);
   procedure Test_Cmp_58311a (Gnattest_T : in out Test) renames Test_Cmp;
--  id:2.2/58311a4ec2c45b28/Cmp/1/0/
   procedure Test_Cmp (Gnattest_T : in out Test) is
   --  crypto-helper.ads:17:4:Cmp
--  end read only

      pragma Unreferenced (Gnattest_T);

      A      : aliased Byte_Array (0 .. 31);
      B      : aliased Byte_Array (0 .. 31);
      Result : Status;

   begin
      --  Test 1: Equal buffers should return Success
      A := (others => 16#42#);
      B := (others => 16#42#);

      Result := Cmp (A, B);
      Assert (Result = Success, "Equal buffers should compare as Success");

      --  Test 2: Different buffers should return Error_Failed
      A := (others => 16#00#);
      B := (others => 16#FF#);

      Result := Cmp (A, B);
      Assert (Result = Error_Failed,
              "Different buffers should compare as Error_Failed");

      --  Test 3: Single byte difference should be detected
      A := (others => 16#AA#);
      B := (others => 16#AA#);
      B (15) := 16#AB#;  --  Change one byte in the middle

      Result := Cmp (A, B);
      Assert (Result = Error_Failed,
              "Single byte difference should be detected");

      --  Test 4: All zeros comparison
      A := (others => 0);
      B := (others => 0);

      Result := Cmp (A, B);
      Assert (Result = Success, "All-zero buffers should compare as Success");

      --  Test 5: First byte different
      A := (others => 16#55#);
      B := (others => 16#55#);
      B (B'First) := 16#56#;

      Result := Cmp (A, B);
      Assert (Result = Error_Failed,
              "First byte difference should be detected");

      --  Test 6: Last byte different
      A := (others => 16#55#);
      B := (others => 16#55#);
      B (B'Last) := 16#56#;

      Result := Cmp (A, B);
      Assert (Result = Error_Failed,
              "Last byte difference should be detected");

--  begin read only
   end Test_Cmp;
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
end Crypto.Helper.Test_Data.Tests;
