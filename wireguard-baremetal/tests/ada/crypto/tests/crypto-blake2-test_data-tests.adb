--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.Blake2.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;
with Interfaces.C;

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
   --  crypto-blake2.ads:38:4:Blake2s
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
   procedure Test_Blake2s_Init (Gnattest_T : in out Test);
   procedure Test_Blake2s_Init_02f8fd (Gnattest_T : in out Test) renames Test_Blake2s_Init;
--  id:2.2/02f8fd6e5952b1aa/Blake2s_Init/1/0/
   procedure Test_Blake2s_Init (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:50:4:Blake2s_Init
--  end read only

      pragma Unreferenced (Gnattest_T);
      State  : aliased Blake2s_State;
      Result : Status;

   begin
      --  Initialize with standard output length (32 bytes)
      Blake2s_Init (State => State, Outlen => 32, Result => Result);
      Assert (Result = Success, "Init with Outlen=32 should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (32),
              "State.Outlen should be 32");
      Assert (State.Buflen = 0, "State.Buflen should be 0 after init");

      --  Initialize with smaller output length (8 bytes)
      Blake2s_Init (State => State, Outlen => 8, Result => Result);
      Assert (Result = Success, "Init with Outlen=8 should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (8),
              "State.Outlen should be 8");

      --  Initialize with maximum output length (32 bytes)
      Blake2s_Init (State => State, Outlen => BLAKE2S_OUTBYTES, Result => Result);
      Assert (Result = Success, "Init with max outlen should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (BLAKE2S_OUTBYTES),
              "State.Outlen should match");

--  begin read only
   end Test_Blake2s_Init;
--  end read only


--  begin read only
   procedure Test_Blake2s_Init_Key (Gnattest_T : in out Test);
   procedure Test_Blake2s_Init_Key_6ed733 (Gnattest_T : in out Test) renames Test_Blake2s_Init_Key;
--  id:2.2/6ed733fb863d5836/Blake2s_Init_Key/1/0/
   procedure Test_Blake2s_Init_Key (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:57:4:Blake2s_Init_Key
--  end read only

      pragma Unreferenced (Gnattest_T);
      State      : aliased Blake2s_State;
      Result     : Status;
      Key_16     : Byte_Array (0 .. 15) := (others => 16#AA#);
      Key_32     : Byte_Array (0 .. 31) := (others => 16#BB#);

   begin
      --  Initialize with 16-byte key
      Blake2s_Init_Key
        (State  => State,
         Outlen => 32,
         Key    => Key_16,
         Result => Result);
      Assert (Result = Success, "Init with 16-byte key should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (32),
              "State.Outlen should be 32");

      --  Initialize with 32-byte key (maximum)
      Blake2s_Init_Key
        (State  => State,
         Outlen => 32,
         Key    => Key_32,
         Result => Result);
      Assert (Result = Success, "Init with 32-byte key should succeed");

      --  Initialize with different output lengths
      Blake2s_Init_Key
        (State  => State,
         Outlen => 8,
         Key    => Key_16,
         Result => Result);
      Assert (Result = Success, "Init with Outlen=8 and key should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (8),
              "State.Outlen should be 8");

--  begin read only
   end Test_Blake2s_Init_Key;
--  end read only


--  begin read only
   procedure Test_Blake2s_Update (Gnattest_T : in out Test);
   procedure Test_Blake2s_Update_8f6ba6 (Gnattest_T : in out Test) renames Test_Blake2s_Update;
--  id:2.2/8f6ba6a74fc7f2d1/Blake2s_Update/1/0/
   procedure Test_Blake2s_Update (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:68:4:Blake2s_Update
--  end read only

      pragma Unreferenced (Gnattest_T);
      State      : aliased Blake2s_State;
      Result     : Status;
      Data_Part1 : Byte_Array := (16#01#, 16#02#, 16#03#, 16#04#);
      Data_Part2 : Byte_Array := (16#05#, 16#06#, 16#07#, 16#08#);
      Empty_Data : Byte_Array (0 .. -1);  --  Empty array

   begin
      --  Initialize state
      Blake2s_Init (State => State, Outlen => 32, Result => Result);
      Assert (Result = Success, "Init should succeed");

      --  Update with first part of data
      Blake2s_Update (State => State, Data => Data_Part1, Result => Result);
      Assert (Result = Success, "First update should succeed");
      Assert (Interfaces.C.size_t (State.Buflen) <=
              Interfaces.C.size_t (BLAKE2S_BLOCKBYTES),
              "Buflen should not exceed block size");

      --  Update with second part of data
      Blake2s_Update (State => State, Data => Data_Part2, Result => Result);
      Assert (Result = Success, "Second update should succeed");

      --  Update with empty data (should be allowed)
      Blake2s_Update (State => State, Data => Empty_Data, Result => Result);
      Assert (Result = Success, "Update with empty data should succeed");

      --  Update with larger data block
      declare
         Large_Data : Byte_Array (0 .. 127);
      begin
         Large_Data := (others => 16#FF#);
         Blake2s_Update (State => State, Data => Large_Data, Result => Result);
         Assert (Result = Success, "Update with large data should succeed");
      end;

--  begin read only
   end Test_Blake2s_Update;
--  end read only


--  begin read only
   procedure Test_Blake2s_Final (Gnattest_T : in out Test);
   procedure Test_Blake2s_Final_4b2d49 (Gnattest_T : in out Test) renames Test_Blake2s_Final;
--  id:2.2/4b2d49a0ced67de6/Blake2s_Final/1/0/
   procedure Test_Blake2s_Final (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:75:4:Blake2s_Final
--  end read only

      pragma Unreferenced (Gnattest_T);
      State      : aliased Blake2s_State;
      Digest     : Byte_Array (0 .. 31);
      Digest2    : Byte_Array (0 .. 31);
      Update_Result : Status;
      Final_Result  : Status;
      Data       : Byte_Array := (Character'Pos ('a'), Character'Pos ('b'),
                                  Character'Pos ('c'), 0);

   begin
      --  Test 1: Simple final without update
      Blake2s_Init (State => State, Outlen => 32, Result => Update_Result);
      Assert (Update_Result = Success, "Init should succeed");

      Blake2s_Final (State => State, Digest => Digest, Result => Final_Result);
      Assert (Final_Result = Success, "Final without update should succeed");
      Assert (Digest'Length = 32, "Digest should be 32 bytes");

      --  Test 2: Final after update
      Blake2s_Init (State => State, Outlen => 32, Result => Update_Result);
      Blake2s_Update (State => State, Data => Data, Result => Update_Result);
      Assert (Update_Result = Success, "Update should succeed");

      Blake2s_Final (State => State, Digest => Digest2, Result => Final_Result);
      Assert (Final_Result = Success, "Final after update should succeed");

      --  The hashes should be different (one is empty, one has data)
      Assert (Digest /= Digest2,
              "Hash of empty vs data should differ");

      --  Test 3: Verify output buffer size matters
      declare
         Small_Digest : Byte_Array (0 .. 7);
      begin
         Blake2s_Init (State => State, Outlen => 8, Result => Update_Result);
         Blake2s_Final (State => State, Digest => Small_Digest,
                        Result => Final_Result);
         Assert (Final_Result = Success, "Final with 8-byte output should succeed");
      end;

--  begin read only
   end Test_Blake2s_Final;
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
