--  Transport - Implementation of WireGuard transport data protocol

with Crypto.KDF;
with Crypto.Helper;
with Messages_Wire;
pragma Unreferenced (Messages_Wire);

package body Transport
  with SPARK_Mode => On
is

   --  Empty input for KDF2(C, "") derivation
   Empty_Input : constant Byte_Array (1 .. 0) := (others => 0);

   --  Instantiate secure wipe for the full handshake record
   procedure Wipe_HS_State is new
     Crypto.Helper.Generic_Memzero (Handshake.Handshake_State);

   ---------------------------------------------------------------------------
   --  Wipe_Handshake (body-local) - Securely erase handshake state
   --
   --  Uses the generic constant-time wipe to guarantee the compiler
   --  cannot optimize the zeroing away.
   ---------------------------------------------------------------------------

   procedure Wipe_Handshake (State : in out Handshake.Handshake_State) is
   begin
      Wipe_HS_State (State);

      --  All fields are zeroed; restore Kind so state-machine checks work
      State.Kind := Handshake.State_Empty;
   end Wipe_Handshake;

   ---------------------------------------------------------------------------
   --  Init_Session
   ---------------------------------------------------------------------------

   procedure Init_Session
     (S      : out Session;
      HS     : in out Handshake.Handshake_State;
      Result : out Status)
   with SPARK_Mode => Off
   is
      Key1 : Crypto.KDF.KDF_Key;
      Key2 : Crypto.KDF.KDF_Key;
   begin
      --  Extract what we need before wiping
      --  Derive two keys: KDF2(Chaining_Key, "")
      --    Key1 = τ1 (initiator's send key)
      --    Key2 = τ2 (initiator's receive key)
      Crypto.KDF.KDF2
        (Key     => HS.Chaining,
         Input   => Empty_Input,
         Output1 => Key1,
         Output2 => Key2,
         Result  => Result);

      if Result /= Success then
         S := Null_Session;
         Wipe_Handshake (HS);
         return;
      end if;

      --  Assign keys based on handshake role
      case HS.Role is
         when Handshake.Role_Initiator =>
            S.Send_Key := Key1;
            S.Receive_Key := Key2;

         when Handshake.Role_Responder =>
            S.Send_Key := Key2;
            S.Receive_Key := Key1;
      end case;

      S.Sender_Index := Unsigned_32 (HS.Local_Index);
      S.Receiver_Index := Unsigned_32 (HS.Remote_Index);
      S.Send_Counter := 0;
      Replay.Reset (S.Replay_Filter);
      S.Valid := True;

      --  Forward secrecy: wipe all ephemeral handshake material
      --  Epriv_i = Epub_i = Epriv_r = Epub_r = C = ε
      Wipe_Handshake (HS);
   end Init_Session;

   ---------------------------------------------------------------------------
   --  Encrypt_Packet
   ---------------------------------------------------------------------------

   procedure Encrypt_Packet
     (S         : in out Session;
      Plaintext : Byte_Array;
      Packet    : out Byte_Array;
      Length    : out Unsigned_16;
      Result    : out Status)
   is
      Header_Size : constant Natural := Messages.Transport_Header_Size;
      Tag_Size    : constant Natural := Crypto.AEAD.Tag_Bytes;
      Total_Len   : constant Natural :=
        Header_Size + Plaintext'Length + Tag_Size;
      PF          : constant Natural := Packet'First;
      Nonce       : Crypto.AEAD.Nonce_Buffer;
   begin
      --  Initialize full output packet (ensures bytes beyond Total_Len are 0)
      Packet := (others => 0);
      Length := 0;

      ----------------------------------------------------------------------
      --  Build 16-byte transport header
      --    [0]     msg_type  = 4
      --    [1..3]  reserved  = 0  (already zeroed)
      --    [4..7]  receiver  = peer's sender index  (LE32)
      --    [8..15] counter   = nonce counter         (LE64)
      ----------------------------------------------------------------------
      Packet (PF) := Messages.Msg_Type_Transport_Data;
      Packet (PF + 4 .. PF + 7) := From_U32 (S.Receiver_Index);
      Packet (PF + 8 .. PF + 15) := From_U64 (S.Send_Counter);

      --  Copy plaintext into payload region (offset Header_Size)
      Packet (PF + Header_Size .. PF + Header_Size + Plaintext'Length - 1) :=
        Plaintext;

      --  Build nonce from send counter
      Crypto.AEAD.Build_Nonce (S.Send_Counter, Nonce);

      --  Encrypt payload in-place; header is AAD, tag is appended
      Crypto.AEAD.Encrypt_In_Place
        (Buffer        => Packet (PF .. PF + Total_Len - 1),
         Plaintext_Len => Plaintext'Length,
         Nonce         => Nonce,
         Key           => S.Send_Key,
         Result        => Result);

      if Result = Success then
         Length := Unsigned_16 (Total_Len);
         S.Send_Counter := S.Send_Counter + 1;
      end if;
   end Encrypt_Packet;

   ---------------------------------------------------------------------------
   --  Decrypt_Packet
   ---------------------------------------------------------------------------

   procedure Decrypt_Packet
     (S       : Session;
      Packet  : in out Byte_Array;
      Length  : out Unsigned_16;
      Counter : out Unsigned_64;
      Result  : out Status)
   is
      Header_Size : constant Natural := Messages.Transport_Header_Size;
      Tag_Size    : constant Natural := Crypto.AEAD.Tag_Bytes;
      CT_With_Tag : constant Natural := Packet'Length - Header_Size;
      PT_Len      : constant Natural := CT_With_Tag - Tag_Size;
      PF          : constant Natural := Packet'First;
      Nonce       : Crypto.AEAD.Nonce_Buffer;
   begin
      --  Default outputs
      Length := 0;
      Counter := 0;

      --  Validate message type
      if Packet (PF) /= Messages.Msg_Type_Transport_Data then
         Result := Error_Failed;
         return;
      end if;

      --  Extract counter from header (LE64 at offset 8)
      declare
         Counter_Bytes : constant Bytes_8 := Packet (PF + 8 .. PF + 15);
      begin
         Counter := To_U64 (Counter_Bytes);
      end;

      --  Build nonce from counter
      Crypto.AEAD.Build_Nonce (Counter, Nonce);

      --  Decrypt in-place: header is AAD, ciphertext+tag after header
      --  On success, plaintext overwrites ciphertext at offset Header_Size
      Crypto.AEAD.Decrypt_In_Place
        (Buffer         => Packet,
         Ciphertext_Len => CT_With_Tag,
         Nonce          => Nonce,
         Key            => S.Receive_Key,
         Result         => Result);

      if Result = Success then
         Length := Unsigned_16 (PT_Len);
      end if;
   end Decrypt_Packet;

end Transport;
