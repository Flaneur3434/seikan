--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.X25519.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.X25519;
with Crypto;
with Crypto.Random;
with Interfaces; use Interfaces;
with Utils;
use type Utils.Status;

--  begin read only
--  end read only
package body Crypto.X25519.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_Generate_Key_Pair (Gnattest_T : in out Test);
   procedure Test_Generate_Key_Pair_75bb7e (Gnattest_T : in out Test) renames Test_Generate_Key_Pair;
--  id:2.2/75bb7e6a34205099/Generate_Key_Pair/1/0/
   procedure Test_Generate_Key_Pair (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:29:4:Generate_Key_Pair
--  end read only

      pragma Unreferenced (Gnattest_T);

      Keys   : Crypto.X25519.Key_Pair;
      Result : Status;
      All_Zero_Public : Boolean := True;
      All_Zero_Secret : Boolean := True;

   begin
      Crypto.X25519.Generate_Key_Pair (Keys, Result);

      AUnit.Assertions.Assert
        (Result = Success,
         "Generate_Key_Pair failed with status: " & Result'Image);

      --  Keys should not be all zeros
      for I in Keys.Pub'Range loop
         if Keys.Pub (I) /= 0 then
            All_Zero_Public := False;
            exit;
         end if;
      end loop;

      for I in Keys.Sec'Range loop
         if Keys.Sec (I) /= 0 then
            All_Zero_Secret := False;
            exit;
         end if;
      end loop;

      AUnit.Assertions.Assert
        (not All_Zero_Public,
         "Public key is all zeros - extremely unlikely");

      AUnit.Assertions.Assert
        (not All_Zero_Secret,
         "Secret key is all zeros - extremely unlikely");

--  begin read only
   end Test_Generate_Key_Pair;
--  end read only


--  begin read only
   procedure Test_Scalar_Mult_Base (Gnattest_T : in out Test);
   procedure Test_Scalar_Mult_Base_899079 (Gnattest_T : in out Test) renames Test_Scalar_Mult_Base;
--  id:2.2/8990790da6cf6dff/Scalar_Mult_Base/1/0/
   procedure Test_Scalar_Mult_Base (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:34:4:Scalar_Mult_Base
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random secret key
      Secret : Crypto.X25519.Secret_Key;
      Public : Crypto.X25519.Public_Key;
      Result : Status;

   begin
      --  Fill secret key with random data
      Crypto.Random.Fill_Random (Utils.Byte_Array (Secret));

      Crypto.X25519.Scalar_Mult_Base (Public, Secret, Result);

      AUnit.Assertions.Assert
        (Result = Success,
         "Scalar_Mult_Base failed with status: " & Result'Image);

      --  The public key should be non-zero
      declare
         All_Zero : Boolean := True;
      begin
         for I in Public'Range loop
            if Public (I) /= 0 then
               All_Zero := False;
               exit;
            end if;
         end loop;
         AUnit.Assertions.Assert
           (not All_Zero,
            "Public key is all zeros");
      end;

--  begin read only
   end Test_Scalar_Mult_Base;
--  end read only


--  begin read only
   procedure Test_Scalar_Mult (Gnattest_T : in out Test);
   procedure Test_Scalar_Mult_864b3a (Gnattest_T : in out Test) renames Test_Scalar_Mult;
--  id:2.2/864b3a493d650526/Scalar_Mult/1/0/
   procedure Test_Scalar_Mult (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:40:4:Scalar_Mult
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Test Diffie-Hellman: Alice and Bob should derive same shared secret
      Alice_Keys : Crypto.X25519.Key_Pair;
      Bob_Keys   : Crypto.X25519.Key_Pair;
      Alice_Shared : Crypto.X25519.Shared_Secret;
      Bob_Shared   : Crypto.X25519.Shared_Secret;
      Result : Status;

   begin
      --  Generate keypairs for Alice and Bob
      Crypto.X25519.Generate_Key_Pair (Alice_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Alice key gen failed");

      Crypto.X25519.Generate_Key_Pair (Bob_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Bob key gen failed");

      --  Alice computes shared secret: Alice_Secret × Bob_Public
      Crypto.X25519.Scalar_Mult
        (Alice_Shared, Alice_Keys.Sec, Bob_Keys.Pub, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Alice DH failed");

      --  Bob computes shared secret: Bob_Secret × Alice_Public
      Crypto.X25519.Scalar_Mult
        (Bob_Shared, Bob_Keys.Sec, Alice_Keys.Pub, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Bob DH failed");

      --  Both should have the same shared secret
      for I in Alice_Shared'Range loop
         AUnit.Assertions.Assert
           (Alice_Shared (I) = Bob_Shared (I),
            "Shared secrets differ at index" & I'Image);
      end loop;

--  begin read only
   end Test_Scalar_Mult;
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
end Crypto.X25519.Test_Data.Tests;
