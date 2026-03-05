--  Transport - Stateless encryption/decryption of WireGuard Type 4 packets

package body Transport
  with SPARK_Mode => On
is

   ---------------------------------------------------------------------------
   --  Encrypt_Packet
   ---------------------------------------------------------------------------

   procedure Encrypt_Packet
     (Key            : Crypto.AEAD.Key_Buffer;
      Receiver_Index : Unsigned_32;
      Counter        : Unsigned_64;
      Plaintext      : Byte_Array;
      Packet         : out Byte_Array;
      Length         : out Unsigned_16;
      Result         : out Status)
   is
      Header_Size : constant Natural := Messages.Transport_Header_Size;
      Tag_Size    : constant Natural := Crypto.AEAD.Tag_Bytes;
      Total_Len   : constant Natural :=
        Header_Size + Plaintext'Length + Tag_Size;
      PF          : constant Natural := Packet'First;
      Nonce       : Crypto.AEAD.Nonce_Buffer;
   begin
      --  Initialize full output packet (ensures bytes beyond Total_Len are 0)
      Packet := [others => 0];
      Length := 0;

      ----------------------------------------------------------------------
      --  Build 16-byte transport header
      --    [0]     msg_type  = 4
      --    [1..3]  reserved  = 0  (already zeroed)
      --    [4..7]  receiver  = peer's sender index  (LE32)
      --    [8..15] counter   = nonce counter         (LE64)
      ----------------------------------------------------------------------
      Packet (PF) := Messages.Msg_Type_Transport_Data;
      Packet (PF + 4 .. PF + 7) := From_U32 (Receiver_Index);
      Packet (PF + 8 .. PF + 15) := From_U64 (Counter);

      --  Copy plaintext into payload region (offset Header_Size)
      --  Skip for keepalive (zero-length plaintext)
      if Plaintext'Length > 0 then
         Packet (PF + Header_Size .. PF + Header_Size + Plaintext'Length - 1) :=
           Plaintext;
      end if;

      --  Build nonce from counter
      Crypto.AEAD.Build_Nonce (Counter, Nonce);

      --  Encrypt payload in-place; header is AAD, tag is appended
      Crypto.AEAD.Encrypt_In_Place
        (Buffer        => Packet (PF .. PF + (Total_Len - 1)),
         Plaintext_Len => Plaintext'Length,
         Nonce         => Nonce,
         Key           => Key,
         Result        => Result);

      if Result = Success then
         Length := Unsigned_16 (Total_Len);
      end if;
   end Encrypt_Packet;

   ---------------------------------------------------------------------------
   --  Encrypt_Into_Buffer
   ---------------------------------------------------------------------------

   procedure Encrypt_Into_Buffer
     (Ref            : Messages.Buffer_Ref;
      Key            : Crypto.AEAD.Key_Buffer;
      Receiver_Index : Unsigned_32;
      Counter        : Unsigned_64;
      Plaintext      : Byte_Array;
      Length         : out Unsigned_16;
      Result         : out Status)
   with SPARK_Mode => Off
   is
      --  Overlay the pool buffer's Data array for zero-copy encryption.
      --  Safe: Packet_Size matches Packet_Buffer.Data'Length.
      Out_Pkt : Byte_Array (0 .. Messages.Packet_Size - 1)
      with Import, Address => Messages.TX_Pool.Get_Ptr (Ref).Data'Address;
   begin
      Encrypt_Packet
        (Key, Receiver_Index, Counter, Plaintext,
         Out_Pkt, Length, Result);
   end Encrypt_Into_Buffer;

   ---------------------------------------------------------------------------
   --  Decrypt_Packet
   ---------------------------------------------------------------------------

   procedure Decrypt_Packet
     (Key     : Crypto.AEAD.Key_Buffer;
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
         Key            => Key,
         Result         => Result);

      if Result = Success then
         Length := Unsigned_16 (PT_Len);
      end if;
   end Decrypt_Packet;

end Transport;
