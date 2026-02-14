with Crypto.KDF;
with Crypto.Helper;

package body Session.Keys
  with SPARK_Mode => On, Refined_State => (KP_State => Next_KP_ID)
is

   ---------------------------------------------------------------------------
   --  Internal Helpers
   ---------------------------------------------------------------------------

   procedure Wipe_HS_State is new
     Crypto.Helper.Generic_Memzero (Handshake.Handshake_State);

   --  Wipe all handshake ephemeral material and reset to State_Empty.
   --  Wraps Generic_Memzero with a postcondition SPARK can verify.
   --  After memzero the Kind field is bit-zero (= State_Empty as the
   --  first enum literal), but the prover can't see through memzero's
   --  untyped wipe, so we set Kind explicitly.
   procedure Wipe_Handshake (HS : in out Handshake.Handshake_State)
   with Depends => (HS => HS), Post => HS.Kind = Handshake.State_Empty
   is
   begin
      Wipe_HS_State (HS);
      HS.Kind := Handshake.State_Empty;
   end Wipe_Handshake;

   --  Empty input for KDF2(C, "") derivation
   Empty_Input : constant Byte_Array (1 .. 0) := [];

   ---------------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------------

   procedure Init is
   begin
      Next_KP_ID := 1;
   end Init;

   ---------------------------------------------------------------------------
   --  Derive_Keypair
   ---------------------------------------------------------------------------

   procedure Derive_Keypair
     (HS     : in out Handshake.Handshake_State;
      Now    : Timer.Clock.Timestamp;
      Result : out Keypair_Result.Result)
   is
      Key1       : Crypto.KDF.KDF_Key;
      Key2       : Crypto.KDF.KDF_Key;
      KP         : Keypair;
      KDF_Result : Utils.Status;
   begin
      --  Derive two keys: KDF2(Chaining_Key, "")
      --    Key1 = τ1 (initiator's send key)
      --    Key2 = τ2 (initiator's receive key)
      Crypto.KDF.KDF2
        (Key     => HS.Chaining,
         Input   => Empty_Input,
         Output1 => Key1,
         Output2 => Key2,
         Result  => KDF_Result);

      if KDF_Result /= Success then
         Wipe_Handshake (HS);
         Result := Keypair_Result.Err (KDF_Error);
      end if;

      --  Build keypair based on role
      case HS.Role is
         when Handshake.Role_Initiator =>
            KP.Send_Key := Key1;
            KP.Receive_Key := Key2;

         when Handshake.Role_Responder =>
            KP.Send_Key := Key2;
            KP.Receive_Key := Key1;
      end case;

      KP.Sender_Index := Unsigned_32 (HS.Local_Index);
      KP.Receiver_Index := Unsigned_32 (HS.Remote_Index);
      KP.Send_Counter := 0;
      Replay.Reset (KP.Replay_Filter);
      KP.Created_At := Now;
      KP.ID := Next_KP_ID;
      KP.Valid := True;
      Next_KP_ID := Next_KP_ID + 1;

      Result := Keypair_Result.Ok (KP);
   end Derive_Keypair;

   ---------------------------------------------------------------------------
   --  Keypair Accessors
   ---------------------------------------------------------------------------

   function Is_Valid (KP : Keypair) return Boolean is
   begin
      return KP.Valid;
   end Is_Valid;

   function Send_Key (KP : Keypair) return Session_Key is
   begin
      return KP.Send_Key;
   end Send_Key;

   function Receive_Key (KP : Keypair) return Session_Key is
   begin
      return KP.Receive_Key;
   end Receive_Key;

   function Receiver_Index (KP : Keypair) return Unsigned_32 is
   begin
      return KP.Receiver_Index;
   end Receiver_Index;
end Session.Keys;
