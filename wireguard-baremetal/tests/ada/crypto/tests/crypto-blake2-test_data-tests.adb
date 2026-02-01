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

with Utils;
use type Utils.Byte_Array;

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
   procedure Test_1_Blake2s (Gnattest_T : in out Test);
   procedure Test_Blake2s_2ee24c (Gnattest_T : in out Test) renames Test_1_Blake2s;
--  id:2.2/2ee24cd6a6986547/Blake2s/1/0/
   procedure Test_1_Blake2s (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:25:4:Blake2s
--  end read only

      pragma Unreferenced (Gnattest_T);

      Hash_Out : Digest_Buffer;
      Result   : Status;

   begin
      --  Test 1: Hash of "abc" (RFC 7693 test vector)
      Blake2s
        (Digest => Hash_Out,
         Data   => Test_Input_Abc,
         Result => Result);

      Assert (Result = Success, "Blake2s should succeed for 'abc'");
      Assert (Byte_Array (Hash_Out) = Expected_Hash_Abc,
              "Blake2s hash of 'abc' should match RFC 7693 test vector");

      --  Test 2: Hash of empty input
      declare
         Empty_Input : constant Byte_Array (1 .. 0) := (others => 0);
      begin
         Blake2s
           (Digest => Hash_Out,
            Data   => Empty_Input,
            Result => Result);

         Assert (Result = Success, "Blake2s should succeed for empty input");
         Assert (Byte_Array (Hash_Out) = Expected_Hash_Empty,
                 "Blake2s hash of empty string should match test vector");
      end;

      --  Test 3: Determinism - same input produces same output
      declare
         Hash_Out_2 : Digest_Buffer;
      begin
         Blake2s
           (Digest => Hash_Out,
            Data   => Test_Input_Abc,
            Result => Result);

         Blake2s
           (Digest => Hash_Out_2,
            Data   => Test_Input_Abc,
            Result => Result);

         Assert (Hash_Out = Hash_Out_2,
                 "Blake2s should be deterministic");
      end;

      --  Test 4: Different inputs produce different outputs
      declare
         Input_1    : constant Byte_Array (0 .. 2) := (1, 2, 3);
         Input_2    : constant Byte_Array (0 .. 2) := (1, 2, 4);
         Hash_Out_1 : Digest_Buffer;
         Hash_Out_2 : Digest_Buffer;
      begin
         Blake2s
           (Digest => Hash_Out_1,
            Data   => Input_1,
            Result => Result);

         Blake2s
           (Digest => Hash_Out_2,
            Data   => Input_2,
            Result => Result);

         Assert (Hash_Out_1 /= Hash_Out_2,
                 "Different inputs should produce different hashes");
      end;

      --  Test 5: Keyed hashing produces different output than unkeyed
      declare
         Test_Key   : constant Key_Buffer := (others => 16#42#);
         Hash_Keyed : Digest_Buffer;
         Hash_Plain : Digest_Buffer;
      begin
         Blake2s
           (Digest => Hash_Plain,
            Data   => Test_Input_Abc,
            Result => Result);

         Blake2s
           (Digest => Hash_Keyed,
            Data   => Test_Input_Abc,
            Key    => Test_Key,
            Result => Result);

         Assert (Result = Success, "Keyed Blake2s should succeed");
         Assert (Hash_Keyed /= Hash_Plain,
                 "Keyed hash should differ from unkeyed hash");
      end;

--  begin read only
   end Test_1_Blake2s;
--  end read only


--  begin read only
   procedure Test_2_Blake2s (Gnattest_T : in out Test);
   procedure Test_Blake2s_0dd8cc (Gnattest_T : in out Test) renames Test_2_Blake2s;
--  id:2.2/0dd8cc188e5cf0d2/Blake2s/0/0/
   procedure Test_2_Blake2s (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:32:4:Blake2s
--  end read only

      pragma Unreferenced (Gnattest_T);

      Test_Data    : constant Byte_Array (0 .. 2) := (16#61#, 16#62#, 16#63#);
      Test_Key     : constant Key_Buffer := (others => 16#42#);
      Hash_Keyed   : Digest_Buffer;
      Hash_Unkeyed : Digest_Buffer;
      Result       : Status;

   begin
      --  Test keyed Blake2s (MAC mode)
      Blake2s
        (Data   => Test_Data,
         Key    => Test_Key,
         Digest => Hash_Keyed,
         Result => Result);

      Assert (Result = Success, "Keyed Blake2s should succeed");

      --  Get unkeyed hash for comparison
      Blake2s
        (Data   => Test_Data,
         Digest => Hash_Unkeyed,
         Result => Result);

      Assert (Result = Success, "Unkeyed Blake2s should succeed");

      --  Keyed and unkeyed should differ
      Assert (Byte_Array (Hash_Keyed) /= Byte_Array (Hash_Unkeyed),
              "Keyed hash should differ from unkeyed hash");

      --  Verify keyed hash is deterministic with same key
      declare
         Hash_Keyed_2 : Digest_Buffer;
      begin
         Blake2s
           (Data   => Test_Data,
            Key    => Test_Key,
            Digest => Hash_Keyed_2,
            Result => Result);

         Assert (Hash_Keyed = Hash_Keyed_2,
                 "Keyed Blake2s should be deterministic");
      end;

      --  Different key should produce different hash
      declare
         Different_Key : Key_Buffer := Test_Key;
         Hash_Different : Digest_Buffer;
      begin
         Different_Key (0) := 16#43#;
         Blake2s
           (Data   => Test_Data,
            Key    => Different_Key,
            Digest => Hash_Different,
            Result => Result);

         Assert (Hash_Keyed /= Hash_Different,
                 "Different keys should produce different hashes");
      end;

--  begin read only
   end Test_2_Blake2s;
--  end read only


--  begin read only
   procedure Test_Blake2s_Init (Gnattest_T : in out Test);
   procedure Test_Blake2s_Init_4089d3 (Gnattest_T : in out Test) renames Test_Blake2s_Init;
--  id:2.2/4089d300103e3cfa/Blake2s_Init/1/0/
   procedure Test_Blake2s_Init (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:44:4:Blake2s_Init
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
   procedure Test_Blake2s_Init_Key_1ba4cb (Gnattest_T : in out Test) renames Test_Blake2s_Init_Key;
--  id:2.2/1ba4cb0f5aa2b3d0/Blake2s_Init_Key/1/0/
   procedure Test_Blake2s_Init_Key (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:51:4:Blake2s_Init_Key
--  end read only

      pragma Unreferenced (Gnattest_T);
      State    : aliased Blake2s_State;
      Result   : Status;
      Test_Key : Key_Buffer := (others => 16#AA#);

   begin
      --  Initialize with key
      Blake2s_Init_Key
        (State  => State,
         Outlen => 32,
         Key    => Test_Key,
         Result => Result);
      Assert (Result = Success, "Init with key should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (32),
              "State.Outlen should be 32");

      --  Initialize with different output length
      Blake2s_Init_Key
        (State  => State,
         Outlen => 8,
         Key    => Test_Key,
         Result => Result);
      Assert (Result = Success, "Init with Outlen=8 and key should succeed");
      Assert (State.Outlen = Interfaces.C.size_t (8),
              "State.Outlen should be 8");

--  begin read only
   end Test_Blake2s_Init_Key;
--  end read only


--  begin read only
   procedure Test_Blake2s_Update (Gnattest_T : in out Test);
   procedure Test_Blake2s_Update_d2a0fc (Gnattest_T : in out Test) renames Test_Blake2s_Update;
--  id:2.2/d2a0fc6eaafc89e0/Blake2s_Update/1/0/
   procedure Test_Blake2s_Update (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:59:4:Blake2s_Update
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
   procedure Test_Blake2s_Final_5c5f63 (Gnattest_T : in out Test) renames Test_Blake2s_Final;
--  id:2.2/5c5f638c72ccc710/Blake2s_Final/1/0/
   procedure Test_Blake2s_Final (Gnattest_T : in out Test) is
   --  crypto-blake2.ads:66:4:Blake2s_Final
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
   --  procedure Test_Blake2s (Gnattest_T : in out Test);
   --  procedure Test_Blake2s_abf864 (Gnattest_T : in out Test) renames Test_Blake2s;
--  id:2.2/abf864841c474017/Blake2s/0/1/
   --  procedure Test_Blake2s (Gnattest_T : in out Test) is
--  end read only
--  
--        pragma Unreferenced (Gnattest_T);
--  
--        Hash_Out : Digest_Buffer;
--        Result   : Status;
--  
--     begin
--        --  Test unkeyed hash of "abc"
--        Blake2s
--          (Digest => Hash_Out,
--           Data   => (Character'Pos ('a'),
--                      Character'Pos ('b'),
--                      Character'Pos ('c')),
--           Result => Result);
--  
--        Assert (Result = Success, "Unkeyed Blake2s should succeed");
--  
--        --  Verify the hash is not all zeros (it did something)
--        declare
--           All_Zeros : Boolean := True;
--        begin
--           for I in Hash_Out'Range loop
--              if Hash_Out (I) /= 0 then
--                 All_Zeros := False;
--                 exit;
--              end if;
--           end loop;
--           Assert (not All_Zeros, "Hash should not be all zeros");
--        end;
--  
--        --  Verify same input produces same output (deterministic)
--        declare
--           Hash_Out2 : Digest_Buffer;
--           Result2   : Status;
--        begin
--           Blake2s
--             (Digest => Hash_Out2,
--              Data   => (Character'Pos ('a'),
--                         Character'Pos ('b'),
--                         Character'Pos ('c')),
--              Result => Result2);
--  
--           Assert (Result2 = Success, "Second unkeyed hash should succeed");
--           Assert (Hash_Out = Hash_Out2, "Same input should produce same hash");
--        end;
--  
--  begin read only
   --  end Test_Blake2s;
--  end read only


--  begin read only
   --  procedure Test_Blake2s (Gnattest_T : in out Test);
   --  procedure Test_Blake2s_c422be (Gnattest_T : in out Test) renames Test_Blake2s;
--  id:2.2/c422bee11d942caf/Blake2s/0/1/
   --  procedure Test_Blake2s (Gnattest_T : in out Test) is
--  end read only
--  
--        pragma Unreferenced (Gnattest_T);
--  
--        --  Keyed BLAKE2s test vector from RFC 7693 Appendix E
--        --  Key: 32 bytes of 00 01 02 ... 1f
--        --  Input: "abc" (3 bytes)
--        Test_Key : Key_Buffer;
--        Hash_Out : Digest_Buffer;
--        Result   : Status;
--  
--     begin
--        --  Initialize test key: 00 01 02 ... 1f
--        for I in Test_Key'Range loop
--           Test_Key (I) := Interfaces.Unsigned_8 (I);
--        end loop;
--  
--        --  Test keyed hash of "abc"
--        Blake2s
--          (Digest => Hash_Out,
--           Data   => Test_Input_Abc,
--           Key    => Test_Key,
--           Result => Result);
--  
--        Assert (Result = Success, "Keyed Blake2s should succeed");
--  
--        --  Verify keyed hash is different from unkeyed hash
--        Assert (Byte_Array (Hash_Out) /= Expected_Hash_Abc,
--                "Keyed hash should differ from unkeyed hash");
--  
--        --  Verify determinism: same key + data = same hash
--        declare
--           Hash_Out_2 : Digest_Buffer;
--        begin
--           Blake2s
--             (Digest => Hash_Out_2,
--              Data   => Test_Input_Abc,
--              Key    => Test_Key,
--              Result => Result);
--           Assert (Result = Success, "Second keyed hash should succeed");
--           Assert (Byte_Array (Hash_Out) = Byte_Array (Hash_Out_2),
--                   "Same key + data should produce same hash");
--        end;
--  
--        --  Verify different key produces different hash
--        declare
--           Different_Key : Key_Buffer := (others => 16#AA#);
--           Hash_Out_3    : Digest_Buffer;
--        begin
--           Blake2s
--             (Digest => Hash_Out_3,
--              Data   => Test_Input_Abc,
--              Key    => Different_Key,
--              Result => Result);
--           Assert (Result = Success, "Different key hash should succeed");
--           Assert (Byte_Array (Hash_Out) /= Byte_Array (Hash_Out_3),
--                   "Different key should produce different hash");
--        end;
--  
--  begin read only
   --  end Test_Blake2s;
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
