--  Transport_Messages - VeriGuard Message Types (libhydrogen)
--
--  This package defines the VeriGuard message types with flexible layout
--  for the libhydrogen backend. Uses Pack pragma instead of hardcoded
--  representation clauses since libhydrogen has different tag sizes.
--
--  Backend: libhydrogen (Gimli-based primitives)
--  Wire format: VeriGuard-specific (NOT WireGuard compatible)
--
--  NOTE: Message sizes are LARGER than WireGuard due to libhydrogen's
--  36-byte AEAD header vs WireGuard's 16-byte Poly1305 tag.

with Interfaces; use Interfaces;
with Utils; use Utils;
with Crypto.KX;
with Crypto.Blake2;
with Crypto.AEAD;

package Transport_Messages
  with SPARK_Mode => On
is
   ---------------------
   --  Field Size Constants (from crypto config)
   ---------------------

   Key_Size       : constant := Crypto.KX.Public_Key_Bytes;
   Hash_Size      : constant := Crypto.Blake2.BLAKE2S_OUTBYTES;
   Aead_Tag_Size  : constant := Crypto.AEAD.Tag_Bytes;
   Cookie_Size    : constant := 16;
   Mac_Size       : constant := 16;
   Timestamp_Size : constant := 12;  --  TAI64N: 8 bytes + 4 nanoseconds
   XChaCha_Nonce_Size : constant := 24;

   --  Encrypted field sizes (plaintext + AEAD tag)
   --  NOTE: With libhydrogen, Aead_Tag_Size = 36, so these are larger
   Encrypted_Static_Size    : constant := Key_Size + Aead_Tag_Size;
   Encrypted_Timestamp_Size : constant := Timestamp_Size + Aead_Tag_Size;
   Encrypted_Empty_Size     : constant := Aead_Tag_Size;
   Encrypted_Cookie_Size    : constant := Cookie_Size + Aead_Tag_Size;

   ---------------------
   --  Byte Array Types for Packed Fields
   ---------------------

   subtype Reserved_Bytes is Byte_Array (0 .. 2);
   subtype Sender_Bytes is Bytes_4;
   subtype Receiver_Bytes is Bytes_4;
   subtype Counter_Bytes is Bytes_8;

   subtype Public_Key_Bytes is Crypto.KX.Public_Key;
   subtype Mac_Bytes is Byte_Array (0 .. Mac_Size - 1);
   subtype XChaCha_Nonce_Bytes is Byte_Array (0 .. XChaCha_Nonce_Size - 1);

   subtype Encrypted_Static_Bytes is
     Byte_Array (0 .. Encrypted_Static_Size - 1);
   subtype Encrypted_Timestamp_Bytes is
     Byte_Array (0 .. Encrypted_Timestamp_Size - 1);
   subtype Encrypted_Empty_Bytes is Byte_Array (0 .. Encrypted_Empty_Size - 1);
   subtype Encrypted_Cookie_Bytes is
     Byte_Array (0 .. Encrypted_Cookie_Size - 1);

   ---------------------
   --  Message Header Sizes (Bytes) - COMPUTED for libhydrogen
   ---------------------

   --  Handshake Initiation: 1 + 3 + 4 + Key + EncStatic + EncTimestamp + Mac + Mac
   Handshake_Init_Size : constant :=
     1 + 3 + 4 + Key_Size + Encrypted_Static_Size + Encrypted_Timestamp_Size +
     Mac_Size + Mac_Size;

   --  Handshake Response: 1 + 3 + 4 + 4 + Key + EncEmpty + Mac + Mac
   Handshake_Response_Size : constant :=
     1 + 3 + 4 + 4 + Key_Size + Encrypted_Empty_Size + Mac_Size + Mac_Size;

   --  Cookie Reply: 1 + 3 + 4 + XChaCha_Nonce + EncCookie
   Cookie_Reply_Size : constant :=
     1 + 3 + 4 + XChaCha_Nonce_Size + Encrypted_Cookie_Size;

   --  Transport Header (fixed, no crypto fields)
   Transport_Header_Size : constant := 16;

   ---------------------
   --  Message Type 1: Handshake Initiation
   ---------------------

   type Message_Handshake_Initiation is record
      Msg_Type            : Unsigned_8;
      Reserved            : Reserved_Bytes;
      Sender              : Sender_Bytes;
      Ephemeral           : Public_Key_Bytes;
      Encrypted_Static    : Encrypted_Static_Bytes;
      Encrypted_Timestamp : Encrypted_Timestamp_Bytes;
      Mac1                : Mac_Bytes;
      Mac2                : Mac_Bytes;
   end record
   with Convention => C, Pack;

   --  NOTE: No representation clause - uses Pack for sequential layout.
   --  Size will be different from WireGuard due to larger AEAD tags.

   ---------------------
   --  Message Type 2: Handshake Response
   ---------------------

   type Message_Handshake_Response is record
      Msg_Type        : Unsigned_8;
      Reserved        : Reserved_Bytes;
      Sender          : Sender_Bytes;
      Receiver        : Receiver_Bytes;
      Ephemeral       : Public_Key_Bytes;
      Encrypted_Empty : Encrypted_Empty_Bytes;
      Mac1            : Mac_Bytes;
      Mac2            : Mac_Bytes;
   end record
   with Convention => C, Pack;

   ---------------------
   --  Message Type 3: Cookie Reply
   ---------------------

   type Message_Cookie_Reply is record
      Msg_Type         : Unsigned_8;
      Reserved         : Reserved_Bytes;
      Receiver         : Receiver_Bytes;
      Nonce            : XChaCha_Nonce_Bytes;
      Encrypted_Cookie : Encrypted_Cookie_Bytes;
   end record
   with Convention => C, Pack;

   ---------------------
   --  Message Type 4: Transport Data Header
   ---------------------

   type Message_Transport_Header is record
      Msg_Type : Unsigned_8;
      Reserved : Reserved_Bytes;
      Receiver : Receiver_Bytes;
      Counter  : Counter_Bytes;
   end record
   with Convention => C, Pack;

   ---------------------
   --  MAC1 Prefix Types
   --
   --  MAC1 is computed over all message bytes preceding the Mac1 field.
   --  These subtypes and extraction functions eliminate the manual byte
   --  assembly that was duplicated across handshake procedures.
   ---------------------

   --  Byte offsets of the Mac1 field within each message
   Mac1_Initiation_Offset : constant :=
     1 + 3 + 4 + Key_Size + Encrypted_Static_Size + Encrypted_Timestamp_Size;

   Mac1_Response_Offset : constant :=
     1 + 3 + 4 + 4 + Key_Size + Encrypted_Empty_Size;

   subtype Initiation_Mac1_Prefix_Bytes is
     Byte_Array (0 .. Mac1_Initiation_Offset - 1);
   subtype Response_Mac1_Prefix_Bytes is
     Byte_Array (0 .. Mac1_Response_Offset - 1);

   --  Extract the bytes preceding Mac1 from a handshake initiation message.
   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation) return Initiation_Mac1_Prefix_Bytes
   with Global => null;

   --  Extract the bytes preceding Mac1 from a handshake response message.
   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response) return Response_Mac1_Prefix_Bytes
   with Global => null;

end Transport_Messages;
