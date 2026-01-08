--  VeriGuard Test Runner
--
--  Main entry point for running all tests.

with Ada.Text_IO;        use Ada.Text_IO;
with Ada.Exceptions;     use Ada.Exceptions;

with Tests;              use Tests;
with Tests.Unit.Crypto;
with Tests.Unit.Wireguard;

procedure Test_Runner is
   Results : Test_Count := (others => 0);

   procedure Run_Test
     (Name : String;
      Test : access procedure)
   is
   begin
      Put ("  Running: " & Name & "... ");
      Test.all;
      Put_Line ("PASS");
      Results.Passed := Results.Passed + 1;
   exception
      when E : others =>
         Put_Line ("FAIL");
         Put_Line ("    " & Exception_Message (E));
         Results.Failed := Results.Failed + 1;
   end Run_Test;

begin
   Put_Line ("VeriGuard Test Suite");
   Put_Line ("====================");
   New_Line;

   --  Crypto Unit Tests
   Put_Line ("Crypto Tests:");
   Run_Test ("Types initialization",
             Tests.Unit.Crypto.Test_Types_Init'Access);
   Run_Test ("Key generation placeholder",
             Tests.Unit.Crypto.Test_Keygen_Placeholder'Access);
   New_Line;

   --  Wireguard Unit Tests
   Put_Line ("Wireguard Tests:");
   Run_Test ("State initialization",
             Tests.Unit.Wireguard.Test_State_Init'Access);
   Run_Test ("Handshake placeholder",
             Tests.Unit.Wireguard.Test_Handshake_Placeholder'Access);
   New_Line;

   Report_Results (Results);
end Test_Runner;
