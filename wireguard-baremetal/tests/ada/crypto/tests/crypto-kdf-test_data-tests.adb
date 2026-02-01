--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.KDF.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.KDF;
with Crypto.Random;
with Utils; use Utils;
with Interfaces; use Interfaces;

--  begin read only
--  end read only
package body Crypto.KDF.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_HMAC_Blake2s (Gnattest_T : in out Test);
   procedure Test_HMAC_Blake2s_6d6aba (Gnattest_T : in out Test) renames Test_HMAC_Blake2s;
--  id:2.2/6d6aba03d4d590b0/HMAC_Blake2s/1/0/
   procedure Test_HMAC_Blake2s (Gnattest_T : in out Test) is
   --  crypto-kdf.ads:32:4:HMAC_Blake2s
--  end read only

      pragma Unreferenced (Gnattest_T);

      Key    : Byte_Array (0 .. 31);
      Data   : Byte_Array (0 .. 63);
      Output : Crypto.KDF.KDF_Key;
      Result : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Key);
      Crypto.Random.Fill_Random (Data);

      --  Test basic HMAC
      Crypto.KDF.HMAC_Blake2s
        (Key    => Key,
         Data   => Data,
         Output => Output,
         Result => Result);

      Assert (Result = Success, "HMAC_Blake2s should succeed");

      --  Output should not be all zeros
      declare
         All_Zero : Boolean := True;
      begin
         for I in Output'Range loop
            if Output (I) /= 0 then
               All_Zero := False;
               exit;
            end if;
         end loop;
         Assert (not All_Zero, "HMAC output should not be all zeros");
      end;

      --  Determinism: same inputs should give same output
      declare
         Output2 : Crypto.KDF.KDF_Key;
      begin
         Crypto.KDF.HMAC_Blake2s
           (Key    => Key,
            Data   => Data,
            Output => Output2,
            Result => Result);

         Assert (Output = Output2, "HMAC should be deterministic");
      end;

      --  Different key should give different output
      declare
         Key2    : Byte_Array := Key;
         Output2 : Crypto.KDF.KDF_Key;
      begin
         Key2 (0) := Key2 (0) xor 16#01#;
         Crypto.KDF.HMAC_Blake2s
           (Key    => Key2,
            Data   => Data,
            Output => Output2,
            Result => Result);

         Assert (Output /= Output2, "Different key should give different HMAC");
      end;

--  begin read only
   end Test_HMAC_Blake2s;
--  end read only


--  begin read only
   procedure Test_KDF1 (Gnattest_T : in out Test);
   procedure Test_KDF1_2d062c (Gnattest_T : in out Test) renames Test_KDF1;
--  id:2.2/2d062ce56dac9887/KDF1/1/0/
   procedure Test_KDF1 (Gnattest_T : in out Test) is
   --  crypto-kdf.ads:49:4:KDF1
--  end read only

      pragma Unreferenced (Gnattest_T);

      Key    : Crypto.KDF.KDF_Key;
      Input  : Byte_Array (0 .. 31);
      Output : Crypto.KDF.KDF_Key;
      Result : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Key);
      Crypto.Random.Fill_Random (Input);

      --  Derive one key
      Crypto.KDF.KDF1
        (Key    => Key,
         Input  => Input,
         Output => Output,
         Result => Result);

      Assert (Result = Success, "KDF1 should succeed");

      --  Output should not be all zeros
      declare
         All_Zero : Boolean := True;
      begin
         for I in Output'Range loop
            if Output (I) /= 0 then
               All_Zero := False;
               exit;
            end if;
         end loop;
         Assert (not All_Zero, "KDF1 output should not be all zeros");
      end;

      --  Determinism
      declare
         Output2 : Crypto.KDF.KDF_Key;
      begin
         Crypto.KDF.KDF1
           (Key    => Key,
            Input  => Input,
            Output => Output2,
            Result => Result);

         Assert (Output = Output2, "KDF1 should be deterministic");
      end;

--  begin read only
   end Test_KDF1;
--  end read only


--  begin read only
   procedure Test_KDF2 (Gnattest_T : in out Test);
   procedure Test_KDF2_2d08b0 (Gnattest_T : in out Test) renames Test_KDF2;
--  id:2.2/2d08b0b454f53802/KDF2/1/0/
   procedure Test_KDF2 (Gnattest_T : in out Test) is
   --  crypto-kdf.ads:61:4:KDF2
--  end read only

      pragma Unreferenced (Gnattest_T);

      Key     : Crypto.KDF.KDF_Key;
      Input   : Byte_Array (0 .. 31);
      Output1 : Crypto.KDF.KDF_Key;
      Output2 : Crypto.KDF.KDF_Key;
      Result  : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Key);
      Crypto.Random.Fill_Random (Input);

      --  Derive two keys
      Crypto.KDF.KDF2
        (Key     => Key,
         Input   => Input,
         Output1 => Output1,
         Output2 => Output2,
         Result  => Result);

      Assert (Result = Success, "KDF2 should succeed");

      --  Outputs should not be all zeros
      declare
         All_Zero1 : Boolean := True;
         All_Zero2 : Boolean := True;
      begin
         for I in Output1'Range loop
            if Output1 (I) /= 0 then
               All_Zero1 := False;
               exit;
            end if;
         end loop;
         for I in Output2'Range loop
            if Output2 (I) /= 0 then
               All_Zero2 := False;
               exit;
            end if;
         end loop;
         Assert (not All_Zero1, "KDF2 output1 should not be all zeros");
         Assert (not All_Zero2, "KDF2 output2 should not be all zeros");
      end;

      --  Two outputs should be different
      Assert (Output1 /= Output2, "KDF2 should produce different outputs");

--  begin read only
   end Test_KDF2;
--  end read only


--  begin read only
   procedure Test_KDF3 (Gnattest_T : in out Test);
   procedure Test_KDF3_c85f7b (Gnattest_T : in out Test) renames Test_KDF3;
--  id:2.2/c85f7b1d413af989/KDF3/1/0/
   procedure Test_KDF3 (Gnattest_T : in out Test) is
   --  crypto-kdf.ads:75:4:KDF3
--  end read only

      pragma Unreferenced (Gnattest_T);

      Key     : Crypto.KDF.KDF_Key;
      Input   : Byte_Array (0 .. 31);
      Output1 : Crypto.KDF.KDF_Key;
      Output2 : Crypto.KDF.KDF_Key;
      Output3 : Crypto.KDF.KDF_Key;
      Result  : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Key);
      Crypto.Random.Fill_Random (Input);

      --  Derive three keys
      Crypto.KDF.KDF3
        (Key     => Key,
         Input   => Input,
         Output1 => Output1,
         Output2 => Output2,
         Output3 => Output3,
         Result  => Result);

      Assert (Result = Success, "KDF3 should succeed");

      --  All three outputs should be different
      Assert (Output1 /= Output2, "KDF3 output1 should differ from output2");
      Assert (Output2 /= Output3, "KDF3 output2 should differ from output3");
      Assert (Output1 /= Output3, "KDF3 output1 should differ from output3");

      --  Verify consistency with KDF2: first two outputs should match
      declare
         KDF2_Out1 : Crypto.KDF.KDF_Key;
         KDF2_Out2 : Crypto.KDF.KDF_Key;
      begin
         Crypto.KDF.KDF2
           (Key     => Key,
            Input   => Input,
            Output1 => KDF2_Out1,
            Output2 => KDF2_Out2,
            Result  => Result);

         Assert (Output1 = KDF2_Out1,
                 "KDF3 output1 should match KDF2 output1");
         Assert (Output2 = KDF2_Out2,
                 "KDF3 output2 should match KDF2 output2");
      end;

--  begin read only
   end Test_KDF3;
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
end Crypto.KDF.Test_Data.Tests;
