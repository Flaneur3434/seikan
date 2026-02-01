--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.KX.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto.KX;
with Crypto.Random;
with Utils; use Utils;

--  begin read only
--  end read only
package body Crypto.KX.Test_Data.Tests is

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
   procedure Test_Generate_Key_Pair_09a7c3 (Gnattest_T : in out Test) renames Test_Generate_Key_Pair;
--  id:2.2/09a7c37a7fd03237/Generate_Key_Pair/1/0/
   procedure Test_Generate_Key_Pair (Gnattest_T : in out Test) is
   --  crypto-kx.ads:35:4:Generate_Key_Pair
--  end read only

      pragma Unreferenced (Gnattest_T);

      Keys   : Crypto.KX.Key_Pair;
      Result : Status;
      All_Zero_Public : Boolean := True;
      All_Zero_Secret : Boolean := True;

   begin
      Crypto.KX.Generate_Key_Pair (Keys, Result);

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
   procedure Test_Derive_Public_Key (Gnattest_T : in out Test);
   procedure Test_Derive_Public_Key_2acfdb (Gnattest_T : in out Test) renames Test_Derive_Public_Key;
--  id:2.2/2acfdbc895604f0d/Derive_Public_Key/1/0/
   procedure Test_Derive_Public_Key (Gnattest_T : in out Test) is
   --  crypto-kx.ads:40:4:Derive_Public_Key
--  end read only

      pragma Unreferenced (Gnattest_T);

      Secret : Crypto.KX.Secret_Key;
      Public : Crypto.KX.Public_Key;
      Result : Status;

   begin
      --  Fill secret key with random data
      Crypto.Random.Fill_Random (Byte_Array (Secret));

      Crypto.KX.Derive_Public_Key (Public, Secret, Result);

      AUnit.Assertions.Assert
        (Result = Success,
         "Derive_Public_Key failed with status: " & Result'Image);

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
   end Test_Derive_Public_Key;
--  end read only


--  begin read only
   procedure Test_DH (Gnattest_T : in out Test);
   procedure Test_DH_f2f1b8 (Gnattest_T : in out Test) renames Test_DH;
--  id:2.2/f2f1b8dff03bff33/DH/1/0/
   procedure Test_DH (Gnattest_T : in out Test) is
   --  crypto-kx.ads:46:4:DH
--  end read only

      pragma Unreferenced (Gnattest_T);

      --  Test Diffie-Hellman: Alice and Bob should derive same shared secret
      Alice_Keys : Crypto.KX.Key_Pair;
      Bob_Keys   : Crypto.KX.Key_Pair;
      Alice_Shared : Crypto.KX.Shared_Secret;
      Bob_Shared   : Crypto.KX.Shared_Secret;
      Result : Status;

   begin
      --  Generate keypairs for Alice and Bob
      Crypto.KX.Generate_Key_Pair (Alice_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Alice key gen failed");

      Crypto.KX.Generate_Key_Pair (Bob_Keys, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Bob key gen failed");

      --  Alice computes shared secret: Alice_Secret × Bob_Public
      Crypto.KX.DH
        (Alice_Shared, Alice_Keys.Sec, Bob_Keys.Pub, Result);
      AUnit.Assertions.Assert
        (Result = Success, "Alice DH failed");

      --  Bob computes shared secret: Bob_Secret × Alice_Public
      Crypto.KX.DH
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
   end Test_DH;
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
end Crypto.KX.Test_Data.Tests;
