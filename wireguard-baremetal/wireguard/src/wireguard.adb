package body Wireguard
   with SPARK_Mode => On
is
   ---------------------------------------------------------------------------
   --  Test procedures for SPARK ownership verification
   --
   --  These demonstrate what SPARK catches (and doesn't catch).
   --  Run: gnatprove -P wireguard.gpr -u wireguard.adb --mode=silver
   ---------------------------------------------------------------------------

   --  CORRECT: Allocate, use, free
   procedure Test_Correct_Usage is
      H : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H);
      if not Packet_Pool.Is_Null (H) then
         --  Use the buffer (via Data address)
         declare
            Addr : constant System.Address := Packet_Pool.Data (H);
            pragma Unreferenced (Addr);
         begin
            null;  --  Do something with Addr
         end;
         Packet_Pool.Free (H);
      end if;
      --  H is null here, no leak
   end Test_Correct_Usage;

   --  CORRECT: Move ownership to another handle
   procedure Test_Move_Ownership is
      H1 : Buffer_Handle;
      H2 : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H1);
      if not Packet_Pool.Is_Null (H1) then
         H2 := H1;  --  Move ownership from H1 to H2
         --  H1 is now invalid (moved)
         Packet_Pool.Free (H2);  --  Free via H2
      end if;
   end Test_Move_Ownership;

   --  CORRECT: Conditional free
   procedure Test_Conditional_Free is
      H : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H);
      --  Even if allocation fails, H is null and no leak occurs
      if not Packet_Pool.Is_Null (H) then
         Packet_Pool.Free (H);
      end if;
   end Test_Conditional_Free;

   ---------------------------------------------------------------------------
   --  BUGS: Uncomment these to see SPARK errors
   ---------------------------------------------------------------------------

   --  BUG: Memory leak - allocated but never freed
   procedure Test_Leak is
      H : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H);
      --  SPARK ERROR: H not reclaimed before end of scope
   end Test_Leak;

   --  BUG: Double free
   procedure Test_Double_Free is
      H : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H);
      if not Packet_Pool.Is_Null (H) then
         Packet_Pool.Free (H);
         Packet_Pool.Free (H);  --  SPARK ERROR: H is null (already freed)
      end if;
   end Test_Double_Free;

   --  BUG: Use after free
   procedure Test_Use_After_Free is
      H    : Buffer_Handle;
      Addr : System.Address;
   begin
      Packet_Pool.Allocate (H);
      if not Packet_Pool.Is_Null (H) then
         Packet_Pool.Free (H);
         Addr := Packet_Pool.Data (H);  --  SPARK ERROR: H is null
      end if;
   end Test_Use_After_Free;

   --  BUG: Use after move
   procedure Test_Use_After_Move is
      H1   : Buffer_Handle;
      H2   : Buffer_Handle;
      Addr : System.Address;
   begin
      Packet_Pool.Allocate (H1);
      if not Packet_Pool.Is_Null (H1) then
         H2 := H1;  --  H1 moved to H2
         Addr := Packet_Pool.Data (H1);  --  SPARK ERROR: H1 was moved
         Packet_Pool.Free (H2);
      end if;
   end Test_Use_After_Move;

   --  BUG: Free after move
   procedure Test_Free_After_Move is
      H1 : Buffer_Handle;
      H2 : Buffer_Handle;
   begin
      Packet_Pool.Allocate (H1);
      if not Packet_Pool.Is_Null (H1) then
         H2 := H1;  --  H1 moved to H2
         Packet_Pool.Free (H1);  --  SPARK ERROR: H1 was moved
         Packet_Pool.Free (H2);
      end if;
   end Test_Free_After_Move;

end Wireguard;
