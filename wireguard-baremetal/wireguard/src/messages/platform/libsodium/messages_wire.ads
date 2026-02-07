--  Messages_Wire - WireGuard Wire-Compatible Message Types (libsodium)
--
--  This package defines the VeriGuard/WireGuard message types with
--  representation clauses that ensure wire compatibility with standard
--  WireGuard implementations.
--
--  Backend: libsodium (X25519, ChaCha20-Poly1305, BLAKE2s)
--  Wire format: Compatible with WireGuard specification

with Interfaces; use Interfaces;
with Utils; use Utils;
with Crypto.KX;
with Crypto.Blake2;
with Crypto.AEAD;

package Messages_Wire
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
   --  Message Header Sizes (Bytes) - WireGuard spec values
   ---------------------

   Handshake_Init_Size     : constant := 148;
   Handshake_Response_Size : constant := 92;
   Cookie_Reply_Size       : constant := 64;
   Transport_Header_Size   : constant := 16;

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
   with Convention => C;

   for Message_Handshake_Initiation use
     record
       Msg_Type            at 0   range 0 .. 7;
       Reserved            at 1   range 0 .. 23;
       Sender              at 4   range 0 .. 31;
       Ephemeral           at 8   range 0 .. 255;
       Encrypted_Static    at 40  range 0 .. 383;
       Encrypted_Timestamp at 88  range 0 .. 223;
       Mac1                at 116 range 0 .. 127;
       Mac2                at 132 range 0 .. 127;
     end record;

   for Message_Handshake_Initiation'Size use Handshake_Init_Size * 8;

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
   with Convention => C;

   for Message_Handshake_Response use
     record
       Msg_Type        at 0  range 0 .. 7;
       Reserved        at 1  range 0 .. 23;
       Sender          at 4  range 0 .. 31;
       Receiver        at 8  range 0 .. 31;
       Ephemeral       at 12 range 0 .. 255;
       Encrypted_Empty at 44 range 0 .. 127;
       Mac1            at 60 range 0 .. 127;
       Mac2            at 76 range 0 .. 127;
     end record;

   for Message_Handshake_Response'Size use Handshake_Response_Size * 8;

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
   with Convention => C;

   for Message_Cookie_Reply use
     record
       Msg_Type         at 0  range 0 .. 7;
       Reserved         at 1  range 0 .. 23;
       Receiver         at 4  range 0 .. 31;
       Nonce            at 8  range 0 .. 191;
       Encrypted_Cookie at 32 range 0 .. 255;
     end record;

   for Message_Cookie_Reply'Size use Cookie_Reply_Size * 8;

   ---------------------
   --  Message Type 4: Transport Data Header
   ---------------------

   type Message_Transport_Header is record
      Msg_Type : Unsigned_8;
      Reserved : Reserved_Bytes;
      Receiver : Receiver_Bytes;
      Counter  : Counter_Bytes;
   end record
   with Convention => C;

   for Message_Transport_Header use
     record
       Msg_Type at 0 range 0 .. 7;
       Reserved at 1 range 0 .. 23;
       Receiver at 4 range 0 .. 31;
       Counter  at 8 range 0 .. 63;
     end record;

   for Message_Transport_Header'Size use Transport_Header_Size * 8;

end Messages_Wire;
