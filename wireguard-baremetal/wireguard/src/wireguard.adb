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
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         --  Use the buffer (via Buf_Ptr)
         declare
            V : TX_Pool.Buffer_View := TX_Pool.Borrow (H);
            pragma Unreferenced (V);
         begin
            null;  --  Access V.Buf_Ptr.Data, V.Buf_Ptr.Len, etc.
         end;
         TX_Pool.Free (H);
      end if;
      --  H is null here, no leak
   end Test_Correct_Usage;

   --  CORRECT: Move ownership to another handle
   procedure Test_Move_Ownership is
      H1 : Buffer_Handle;
      H2 : Buffer_Handle;
   begin
      TX_Pool.Allocate (H1);
      if not TX_Pool.Is_Null (H1) then
         TX_Pool.Move
           (From => H1, To => H2);  --  Explicit ownership transfer
         --  H1 is now null (moved)
         TX_Pool.Free (H2);  --  Free via H2

      end if;
   end Test_Move_Ownership;

   --  CORRECT: Conditional free
   procedure Test_Conditional_Free is
      H : Buffer_Handle;
   begin
      TX_Pool.Allocate (H);
      --  Even if allocation fails, H is null and no leak occurs
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Free (H);
      end if;
   end Test_Conditional_Free;

   ---------------------------------------------------------------------------
   --  BUGS: Uncomment these to see SPARK errors
   ---------------------------------------------------------------------------

   --  BUG: Memory leak - allocated but never freed
   procedure Test_Leak is
      H : Buffer_Handle;
   begin
      TX_Pool.Allocate (H);
      --  SPARK ERROR: H not reclaimed before end of scope
   end Test_Leak;

   --  BUG: Double free
   procedure Test_Double_Free is
      H : Buffer_Handle;
   begin
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Free (H);
         TX_Pool.Free (H);  --  SPARK ERROR: H is null (already freed)

      end if;
   end Test_Double_Free;

   --  BUG: Use after free
   procedure Test_Use_After_Free is
      H : Buffer_Handle;
      V : Buffer_View;
   begin
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Free (H);
         V := TX_Pool.Borrow (H);  --  SPARK ERROR: H is null

      end if;
   end Test_Use_After_Free;

   --  BUG: Use after move
   procedure Test_Use_After_Move is
      H1 : Buffer_Handle;
      H2 : Buffer_Handle;
      V1 : Buffer_View;
   begin
      TX_Pool.Allocate (H1);
      if not TX_Pool.Is_Null (H1) then
         TX_Pool.Move (From => H1, To => H2);  --  H1 moved to H2
         V1 :=
           TX_Pool.Borrow (H1);  --  SPARK ERROR: H1 was moved (is null)
         TX_Pool.Free (H2);
      end if;
   end Test_Use_After_Move;

   --  BUG: Free after move
   procedure Test_Free_After_Move is
      H1 : Buffer_Handle;
      H2 : Buffer_Handle;
   begin
      TX_Pool.Allocate (H1);
      if not TX_Pool.Is_Null (H1) then
         TX_Pool.Move (From => H1, To => H2);  --  H1 moved to H2
         TX_Pool.Free (H1);  --  SPARK ERROR: H1 was moved (is null)
         TX_Pool.Free (H2);
      end if;
   end Test_Free_After_Move;

   ---------------------------------------------------------------------------
   --  BORROW TRACKING TESTS
   ---------------------------------------------------------------------------

   --  CORRECT: Mutable borrow with explicit return
   procedure Test_Correct_Mutable_Borrow is
      H   : Buffer_Handle;
      Ref : Buffer_Ref;
   begin
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Borrow_Mut (Handle => H, Ref => Ref);
         --  ... modify buffer via Ref_Data (Ref) ...
         TX_Pool.Return_Ref (Handle => H, Ref => Ref);  --  Return borrow
         TX_Pool.Free (H);  --  OK: borrow was returned
      end if;
   end Test_Correct_Mutable_Borrow;

   --  BUG: Free while mutable borrow is active
   procedure Test_Free_While_Borrowed is
      H   : Buffer_Handle;
      Ref : Buffer_Ref;
   begin
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Borrow_Mut (Handle => H, Ref => Ref);
         --  Forgot to return the borrow!
         TX_Pool.Free (H);  --  SPARK ERROR: Is_Mutably_Borrowed (H)
      end if;
   end Test_Free_While_Borrowed;

   --  BUG: Double mutable borrow
   procedure Test_Double_Mutable_Borrow is
      H    : Buffer_Handle;
      Ref1 : Buffer_Ref;
      Ref2 : Buffer_Ref;
   begin
      TX_Pool.Allocate (H);
      if not TX_Pool.Is_Null (H) then
         TX_Pool.Borrow_Mut (Handle => H, Ref => Ref1);
         TX_Pool.Borrow_Mut (Handle => H, Ref => Ref2);  --  SPARK ERROR
         TX_Pool.Return_Ref (Handle => H, Ref => Ref1);
         TX_Pool.Return_Ref (Handle => H, Ref => Ref2);
         TX_Pool.Free (H);
      end if;
   end Test_Double_Mutable_Borrow;

end Wireguard;
