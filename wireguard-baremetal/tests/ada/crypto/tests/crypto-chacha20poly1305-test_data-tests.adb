--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.ChaCha20Poly1305.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.Random;

--  begin read only
--  end read only
package body Crypto.ChaCha20Poly1305.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_Encrypt (Gnattest_T : in out Test);
   procedure Test_Encrypt_7c9a14 (Gnattest_T : in out Test) renames Test_Encrypt;
--  id:2.2/7c9a1487baa5184e/Encrypt/1/0/
   procedure Test_Encrypt (Gnattest_T : in out Test) is
   --  crypto-chacha20poly1305.ads:29:4:Encrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random test data
      Ctx        : Context;
      Plaintext  : Byte_Array (0 .. 63);
      Ad         : Byte_Array (0 .. 15);
      Ciphertext : Byte_Array (0 .. Plaintext'Length + Tag_Bytes - 1);
      Result     : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Byte_Array (Ctx.N));
      Crypto.Random.Fill_Random (Byte_Array (Ctx.K));
      Crypto.Random.Fill_Random (Plaintext);
      Crypto.Random.Fill_Random (Ad);

      --  Encrypt the test plaintext
      Encrypt
        (Plaintext  => Plaintext,
         Ad         => Ad,
         Ctx        => Ctx,
         Ciphertext => Ciphertext,
         Result     => Result);

      --  Check encryption succeeded
      Assert (Result = Success, "Encrypt should succeed");

      --  Verify ciphertext is not all zeros (encryption did something)
      declare
         All_Zeros : Boolean := True;
      begin
         for I in Ciphertext'Range loop
            if Ciphertext (I) /= 0 then
               All_Zeros := False;
               exit;
            end if;
         end loop;
         Assert (not All_Zeros, "Ciphertext should not be all zeros");
      end;

      --  Verify round-trip: decrypt and compare
      declare
         Decrypted  : Byte_Array (Plaintext'Range);
         Dec_Result : Status;
      begin
         Decrypt
           (Ciphertext => Ciphertext,
            Ad         => Ad,
            Ctx        => Ctx,
            Plaintext  => Decrypted,
            Result     => Dec_Result);

         Assert (Dec_Result = Success, "Decrypt should succeed");
         Assert (Decrypted = Plaintext, "Round-trip should match");
      end;

--  begin read only
   end Test_Encrypt;
--  end read only


--  begin read only
   procedure Test_Decrypt (Gnattest_T : in out Test);
   procedure Test_Decrypt_d610aa (Gnattest_T : in out Test) renames Test_Decrypt;
--  id:2.2/d610aaa19eeeaed0/Decrypt/1/0/
   procedure Test_Decrypt (Gnattest_T : in out Test) is
   --  crypto-chacha20poly1305.ads:41:4:Decrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random test data
      Ctx             : Context;
      Original_Pt     : Byte_Array (0 .. 63);
      Ad              : Byte_Array (0 .. 15);
      Ciphertext      : Byte_Array (0 .. Original_Pt'Length + Tag_Bytes - 1);
      Decrypted_Pt    : Byte_Array (Original_Pt'Range);
      Enc_Result      : Status;
      Dec_Result      : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Byte_Array (Ctx.N));
      Crypto.Random.Fill_Random (Byte_Array (Ctx.K));
      Crypto.Random.Fill_Random (Original_Pt);
      Crypto.Random.Fill_Random (Ad);

      --  First encrypt to get valid ciphertext
      Encrypt
        (Plaintext  => Original_Pt,
         Ad         => Ad,
         Ctx        => Ctx,
         Ciphertext => Ciphertext,
         Result     => Enc_Result);
      Assert (Enc_Result = Success, "Encrypt for decrypt test should succeed");

      --  Test successful decryption
      Decrypt
        (Ciphertext => Ciphertext,
         Ad         => Ad,
         Ctx        => Ctx,
         Plaintext  => Decrypted_Pt,
         Result     => Dec_Result);

      Assert (Dec_Result = Success, "Decrypt should succeed with valid tag");
      Assert (Decrypted_Pt = Original_Pt, "Decrypted text should match");

      --  Test decryption with tampered ciphertext (should fail)
      declare
         Tampered        : Byte_Array := Ciphertext;
         Tampered_Pt     : Byte_Array (Original_Pt'Range);
         Tampered_Result : Status;
      begin
         --  Flip a bit in the ciphertext
         Tampered (0) := Tampered (0) xor 16#01#;

         Decrypt
           (Ciphertext => Tampered,
            Ad         => Ad,
            Ctx        => Ctx,
            Plaintext  => Tampered_Pt,
            Result     => Tampered_Result);

         Assert (Tampered_Result /= Success,
                 "Decrypt should fail with tampered ciphertext");
      end;

--  begin read only
   end Test_Decrypt;
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
end Crypto.ChaCha20Poly1305.Test_Data.Tests;
