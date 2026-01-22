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

   use Utils;  --  For From_Array and Byte_Span operations

--  begin read only
--  end read only

--  begin read only
   procedure Test_Encrypt (Gnattest_T : in out Test);
   procedure Test_Encrypt_11929c (Gnattest_T : in out Test) renames Test_Encrypt;
--  id:2.2/11929c81a94cfb4a/Encrypt/1/0/
   procedure Test_Encrypt (Gnattest_T : in out Test) is
   --  crypto-chacha20poly1305.ads:40:4:Encrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random test data
      Plaintext  : aliased Byte_Array (0 .. 63);
      Ad         : aliased Byte_Array (0 .. 15);
      Ciphertext : aliased Byte_Array (0 .. Plaintext'Length + Tag_Bytes - 1);
      Nonce_Buf  : Nonce_Buffer;
      Key_Buf    : Key_Buffer;
      Result     : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Plaintext);
      Crypto.Random.Fill_Random (Ad);

      --  Encrypt the test plaintext
      Encrypt
        (Plaintext_Span  => From_Address (Plaintext'Address, Plaintext'Length),
         Ad_Span         => From_Address (Ad'Address, Ad'Length),
         Key             => Key_Buf,
         Nonce           => Nonce_Buf,
         Ciphertext_Span =>
           From_Address (Ciphertext'Address, Ciphertext'Length),
         Result          => Result);

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
         Decrypted  : aliased Byte_Array (Plaintext'Range);
         Dec_Result : Status;
      begin
         Decrypt
           (Ciphertext_Span =>
              From_Address (Ciphertext'Address, Ciphertext'Length),
            Ad_Span         => From_Address (Ad'Address, Ad'Length),
            Key             => Key_Buf,
            Nonce           => Nonce_Buf,
            Plaintext_Span  =>
              From_Address (Decrypted'Address, Decrypted'Length),
            Result          => Dec_Result);

         Assert (Dec_Result = Success, "Decrypt should succeed");
         Assert (Decrypted = Plaintext, "Round-trip should match");
      end;

--  begin read only
   end Test_Encrypt;
--  end read only


--  begin read only
   procedure Test_Decrypt (Gnattest_T : in out Test);
   procedure Test_Decrypt_8e02e0 (Gnattest_T : in out Test) renames Test_Decrypt;
--  id:2.2/8e02e0521e73a5f7/Decrypt/1/0/
   procedure Test_Decrypt (Gnattest_T : in out Test) is
   --  crypto-chacha20poly1305.ads:58:4:Decrypt
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random test data
      Original_Pt     : aliased Byte_Array (0 .. 63);
      Ad              : aliased Byte_Array (0 .. 15);
      Ciphertext      : aliased Byte_Array
        (0 .. Original_Pt'Length + Tag_Bytes - 1);
      Decrypted_Pt    : aliased Byte_Array (Original_Pt'Range);
      Nonce_Buf       : Nonce_Buffer;
      Key_Buf         : Key_Buffer;
      Enc_Result      : Status;
      Dec_Result      : Status;

   begin
      --  Fill with random data
      Crypto.Random.Fill_Random (Nonce_Buf);
      Crypto.Random.Fill_Random (Key_Buf);
      Crypto.Random.Fill_Random (Original_Pt);
      Crypto.Random.Fill_Random (Ad);

      --  First encrypt to get valid ciphertext
      Encrypt
        (Plaintext_Span  =>
           From_Address (Original_Pt'Address, Original_Pt'Length),
         Ad_Span         => From_Address (Ad'Address, Ad'Length),
         Key             => Key_Buf,
         Nonce           => Nonce_Buf,
         Ciphertext_Span =>
           From_Address (Ciphertext'Address, Ciphertext'Length),
         Result          => Enc_Result);
      Assert (Enc_Result = Success, "Encrypt for decrypt test should succeed");

      --  Test successful decryption
      Decrypt
        (Ciphertext_Span =>
           From_Address (Ciphertext'Address, Ciphertext'Length),
         Ad_Span         => From_Address (Ad'Address, Ad'Length),
         Key             => Key_Buf,
         Nonce           => Nonce_Buf,
         Plaintext_Span  =>
           From_Address (Decrypted_Pt'Address, Decrypted_Pt'Length),
         Result          => Dec_Result);

      Assert (Dec_Result = Success, "Decrypt should succeed with valid tag");
      Assert (Decrypted_Pt = Original_Pt, "Decrypted text should match");

      --  Test decryption with tampered ciphertext (should fail)
      declare
         Tampered        : aliased Byte_Array := Ciphertext;
         Tampered_Pt     : aliased Byte_Array (Original_Pt'Range);
         Tampered_Result : Status;
      begin
         --  Flip a bit in the ciphertext
         Tampered (0) := Tampered (0) xor 16#01#;

         Decrypt
           (Ciphertext_Span =>
              From_Address (Tampered'Address, Tampered'Length),
            Ad_Span         => From_Address (Ad'Address, Ad'Length),
            Key             => Key_Buf,
            Nonce           => Nonce_Buf,
            Plaintext_Span  =>
              From_Address (Tampered_Pt'Address, Tampered_Pt'Length),
            Result          => Tampered_Result);

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
