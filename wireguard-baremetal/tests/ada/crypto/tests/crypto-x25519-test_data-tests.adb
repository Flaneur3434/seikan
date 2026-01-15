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
use type Crypto.Status;
use type Crypto.Unsigned_8;

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
   procedure Test_Generate_Key_Pair_957c1c (Gnattest_T : in out Test) renames Test_Generate_Key_Pair;
--  id:2.2/957c1ce56d21d064/Generate_Key_Pair/1/0/
   procedure Test_Generate_Key_Pair (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:10:4:Generate_Key_Pair
--  end read only

      pragma Unreferenced (Gnattest_T);

      Keys   : Crypto.Key_Pair;
      Result : Crypto.Status;
      All_Zero_Public : Boolean := True;
      All_Zero_Secret : Boolean := True;

   begin
      Crypto.X25519.Generate_Key_Pair (Keys, Result);

      AUnit.Assertions.Assert
        (Result = Crypto.Success,
         "Generate_Key_Pair failed with status: " & Result'Image);

      --  Keys should not be all zeros
      for I in Keys.Public_Key'Range loop
         if Keys.Public_Key (I) /= 0 then
            All_Zero_Public := False;
            exit;
         end if;
      end loop;

      for I in Keys.Secret_Key'Range loop
         if Keys.Secret_Key (I) /= 0 then
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
   procedure Test_Scalar_Mult_Base_b4d251 (Gnattest_T : in out Test) renames Test_Scalar_Mult_Base;
--  id:2.2/b4d2519aa2ea5bc9/Scalar_Mult_Base/1/0/
   procedure Test_Scalar_Mult_Base (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:17:4:Scalar_Mult_Base
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Generate random secret key
      Secret : Crypto.X25519_Secret_Key;
      Public : Crypto.X25519_Public_Key;
      Result : Crypto.Status;

   begin
      --  Fill secret key with random data
      Crypto.Random.Fill_Random (Crypto.Byte_Array (Secret));

      Crypto.X25519.Scalar_Mult_Base (Public, Secret, Result);

      AUnit.Assertions.Assert
        (Result = Crypto.Success,
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
   procedure Test_Scalar_Mult_6f3f6d (Gnattest_T : in out Test) renames Test_Scalar_Mult;
--  id:2.2/6f3f6dd9a4e3ad84/Scalar_Mult/1/0/
   procedure Test_Scalar_Mult (Gnattest_T : in out Test) is
   --  crypto-x25519.ads:27:4:Scalar_Mult
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Test Diffie-Hellman: Alice and Bob should derive same shared secret
      Alice_Keys : Crypto.Key_Pair;
      Bob_Keys   : Crypto.Key_Pair;
      Alice_Shared : Crypto.X25519_Shared_Secret;
      Bob_Shared   : Crypto.X25519_Shared_Secret;
      Result : Crypto.Status;

   begin
      --  Generate keypairs for Alice and Bob
      Crypto.X25519.Generate_Key_Pair (Alice_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Crypto.Success, "Alice key gen failed");

      Crypto.X25519.Generate_Key_Pair (Bob_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Crypto.Success, "Bob key gen failed");

      --  Alice computes shared secret: Alice_Secret × Bob_Public
      Crypto.X25519.Scalar_Mult
        (Alice_Shared, Alice_Keys.Secret_Key, Bob_Keys.Public_Key, Result);
      AUnit.Assertions.Assert
        (Result = Crypto.Success, "Alice DH failed");

      --  Bob computes shared secret: Bob_Secret × Alice_Public
      Crypto.X25519.Scalar_Mult
        (Bob_Shared, Bob_Keys.Secret_Key, Alice_Keys.Public_Key, Result);
      AUnit.Assertions.Assert
        (Result = Crypto.Success, "Bob DH failed");

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
