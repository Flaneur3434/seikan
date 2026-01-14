--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.Random.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.Random;
with Interfaces;
use type Interfaces.Unsigned_8;

--  begin read only
--  end read only
package body Crypto.Random.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_Fill_Random (Gnattest_T : in out Test);
   procedure Test_Fill_Random_3b8490 (Gnattest_T : in out Test) renames Test_Fill_Random;
--  id:2.2/3b84907a51458a25/Fill_Random/1/0/
   procedure Test_Fill_Random (Gnattest_T : in out Test) is
   --  crypto-random.ads:10:4:Fill_Random
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Test 1: Buffer should not be all zeros after Fill_Random
      Buffer : Crypto.Random.Byte_Array (1 .. 32) := (others => 0);
      All_Zero : Boolean := True;

      --  Test 2: Two calls should produce different results
      Buffer2 : Crypto.Random.Byte_Array (1 .. 32) := (others => 0);
      Same : Boolean := True;

   begin
      --  Test 1: Fill buffer and verify not all zeros
      Crypto.Random.Fill_Random (Buffer);

      for I in Buffer'Range loop
         if Buffer (I) /= 0 then
            All_Zero := False;
            exit;
         end if;
      end loop;

      AUnit.Assertions.Assert
        (not All_Zero,
         "Fill_Random produced all zeros - extremely unlikely for 32 bytes");

      --  Test 2: Second call should produce different values
      Crypto.Random.Fill_Random (Buffer2);

      for I in Buffer'Range loop
         if Buffer (I) /= Buffer2 (I) then
            Same := False;
            exit;
         end if;
      end loop;

      AUnit.Assertions.Assert
        (not Same,
         "Two Fill_Random calls produced identical buffers - extremely unlikely");

--  begin read only
   end Test_Fill_Random;
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
end Crypto.Random.Test_Data.Tests;
