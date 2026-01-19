--  This package has been generated automatically by GNATtest.
--  You are allowed to add your code to the bodies of test routines.
--  Such changes will be kept during further regeneration of this file.
--  All code placed outside of test routine bodies will be lost. The
--  code intended to set up and tear down the test environment should be
--  placed into Crypto.Test_Data.

with AUnit.Assertions; use AUnit.Assertions;
with System.Assertions;

--  begin read only
--  id:2.2/00/
--
--  This section can be used to add with clauses if necessary.
--
--  end read only

with Crypto;
use type Crypto.Status;

--  begin read only
--  end read only
package body Crypto.Test_Data.Tests is

--  begin read only
--  id:2.2/01/
--
--  This section can be used to add global variables and other elements.
--
--  end read only

--  begin read only
--  end read only

--  begin read only
   procedure Test_Is_Success (Gnattest_T : in out Test);
   procedure Test_Is_Success_cdfc80 (Gnattest_T : in out Test) renames Test_Is_Success;
--  id:2.2/cdfc80dfc79170b0/Is_Success/1/0/
   procedure Test_Is_Success (Gnattest_T : in out Test) is
   --  crypto.ads:14:4:Is_Success
--  end read only

      pragma Unreferenced (Gnattest_T);

   begin
      --  Test that Is_Success returns True only for Success
      AUnit.Assertions.Assert
        (Crypto.Is_Success (Crypto.Success) = True,
         "Is_Success should return True for Success");

      AUnit.Assertions.Assert
        (Crypto.Is_Success (Crypto.Error_Failed) = False,
         "Is_Success should return False for Error_Failed");

      AUnit.Assertions.Assert
        (Crypto.Is_Success (Crypto.Error_Invalid_Argument) = False,
         "Is_Success should return False for Error_Invalid_Argument");

--  begin read only
   end Test_Is_Success;
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
end Crypto.Test_Data.Tests;
