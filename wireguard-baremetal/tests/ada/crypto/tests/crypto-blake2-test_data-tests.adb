--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.Blake2.Test_Data.

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
package body Crypto.Blake2.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

   --  BLAKE2s test vector from RFC 7693 Appendix A
   --  Input: "abc" (3 bytes)
   --  Output (32 bytes): 508c5e8c327c14e2 e1a72ba34eeb452f
   --                     37458b209ed63a29 4d999b4c86675982
   Test_Input_Abc : constant Byte_Array (0 .. 2) := (16#61#, 16#62#, 16#63#);
   Expected_Hash_Abc : constant Byte_Array (0 .. 31) := (
      16#50#, 16#8c#, 16#5e#, 16#8c#, 16#32#, 16#7c#, 16#14#, 16#e2#,
      16#e1#, 16#a7#, 16#2b#, 16#a3#, 16#4e#, 16#eb#, 16#45#, 16#2f#,
      16#37#, 16#45#, 16#8b#, 16#20#, 16#9e#, 16#d6#, 16#3a#, 16#29#,
      16#4d#, 16#99#, 16#9b#, 16#4c#, 16#86#, 16#67#, 16#59#, 16#82#
   );

   --  Empty input test vector
   --  BLAKE2s-256 of empty string
   Expected_Hash_Empty : constant Byte_Array (0 .. 31) := (
      16#69#, 16#21#, 16#7a#, 16#30#, 16#79#, 16#90#, 16#80#, 16#94#,
      16#e1#, 16#11#, 16#21#, 16#d0#, 16#42#, 16#35#, 16#4a#, 16#7c#,
      16#1f#, 16#55#, 16#b6#, 16#48#, 16#2c#, 16#a1#, 16#a5#, 16#1e#,
      16#1b#, 16#25#, 16#0d#, 16#fd#, 16#1e#, 16#d0#, 16#ee#, 16#f9#
   );

--  begin read only
--  end read only

--  begin read only
   procedure Test_Blake2s (Gnattest_T : in out Test);
   procedure Test_Blake2s_440ffe (Gnattest_T : in out Test) renames Test_Blake2s;
--  id:2.2/440ffea396742f90/Blake2s/1/0/
   procedure Test_Blake2s (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:4:4:Blake2s
--  end read only

      pragma Unreferenced (Gnattest_T);

      Hash_Out   : Byte_Array (0 .. 31);
      Result     : Status;
      Empty_Key  : constant Byte_Array (1 .. 0) := (others => 0);

   begin
      --  Test 1: Hash of "abc" (RFC 7693 test vector)
      Blake2s
        (Buffer_Out => Hash_Out,
         Buffer_In  => Test_Input_Abc,
         Key_Buffer => Empty_Key,
         Result     => Result);

      Assert (Result = Success, "Blake2s should succeed for 'abc'");
      Assert (Hash_Out = Expected_Hash_Abc,
              "Blake2s hash of 'abc' should match RFC 7693 test vector");

      --  Test 2: Hash of empty input
      declare
         Empty_Input : constant Byte_Array (1 .. 0) := (others => 0);
      begin
         Blake2s
           (Buffer_Out => Hash_Out,
            Buffer_In  => Empty_Input,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Assert (Result = Success, "Blake2s should succeed for empty input");
         Assert (Hash_Out = Expected_Hash_Empty,
                 "Blake2s hash of empty string should match test vector");
      end;

      --  Test 3: Determinism - same input produces same output
      declare
         Hash_Out_2 : Byte_Array (0 .. 31);
      begin
         Blake2s
           (Buffer_Out => Hash_Out,
            Buffer_In  => Test_Input_Abc,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Blake2s
           (Buffer_Out => Hash_Out_2,
            Buffer_In  => Test_Input_Abc,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Assert (Hash_Out = Hash_Out_2,
                 "Blake2s should be deterministic");
      end;

      --  Test 4: Different inputs produce different outputs
      declare
         Input_1    : constant Byte_Array (0 .. 2) := (1, 2, 3);
         Input_2    : constant Byte_Array (0 .. 2) := (1, 2, 4);
         Hash_Out_1 : Byte_Array (0 .. 31);
         Hash_Out_2 : Byte_Array (0 .. 31);
      begin
         Blake2s
           (Buffer_Out => Hash_Out_1,
            Buffer_In  => Input_1,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Blake2s
           (Buffer_Out => Hash_Out_2,
            Buffer_In  => Input_2,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Assert (Hash_Out_1 /= Hash_Out_2,
                 "Different inputs should produce different hashes");
      end;

      --  Test 5: Keyed hashing produces different output than unkeyed
      declare
         Key        : constant Byte_Array (0 .. 31) := (others => 16#42#);
         Hash_Keyed : Byte_Array (0 .. 31);
         Hash_Plain : Byte_Array (0 .. 31);
      begin
         Blake2s
           (Buffer_Out => Hash_Plain,
            Buffer_In  => Test_Input_Abc,
            Key_Buffer => Empty_Key,
            Result     => Result);

         Blake2s
           (Buffer_Out => Hash_Keyed,
            Buffer_In  => Test_Input_Abc,
            Key_Buffer => Key,
            Result     => Result);

         Assert (Result = Success, "Keyed Blake2s should succeed");
         Assert (Hash_Keyed /= Hash_Plain,
                 "Keyed hash should differ from unkeyed hash");
      end;

--  begin read only
   end Test_Blake2s;
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
end Crypto.Blake2.Test_Data.Tests;
