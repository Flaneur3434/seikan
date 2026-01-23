--  Transport - WireGuard Transport Layer
--
--  WireGuard message types with representation clauses for zero-copy
--  packet parsing. Records can be overlaid on raw packet memory using
--  Unchecked_Conversion or address overlays, similar to casting to
--  packed C structs.
--
--  All multi-byte integer fields use Byte_Array to avoid alignment
--  issues. Use Utils.To_U32/To_U64 for conversion to native integers.

with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.X25519;
with Crypto.Blake2;
with Crypto.ChaCha20Poly1305;
with Crypto.TAI64N;

package Transport
  with SPARK_Mode => On
is
   ---------------------
   --  Message Type Constants
   ---------------------

   Msg_Type_Handshake_Initiation : constant Unsigned_8 := 1;
   Msg_Type_Handshake_Response   : constant Unsigned_8 := 2;
   Msg_Type_Cookie_Reply         : constant Unsigned_8 := 3;
   Msg_Type_Transport_Data       : constant Unsigned_8 := 4;

   ---------------------
   --  Field Size Constants
   ---------------------

   Key_Size       : constant := Crypto.X25519.Scalarmult_Bytes;
   Hash_Size      : constant := Crypto.Blake2.BLAKE2S_OUTBYTES;
   Aead_Tag_Size  : constant := Crypto.ChaCha20Poly1305.Tag_Bytes;
   Cookie_Size    : constant := 16;
   Mac_Size       : constant := 16;
   Timestamp_Size : constant := 12;  --  TAI64N: 8 bytes + 4 nanoseconds
   --  Cookie Reply uses XChaCha20Poly1305 (24-byte nonce), not the regular
   --  ChaCha20Poly1305 IETF (12-byte nonce) used elsewhere in WireGuard.
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
   subtype Sender_Bytes is Bytes_4;      --  Use Utils.To_U32 for conversion
   subtype Receiver_Bytes is Bytes_4;    --  Use Utils.To_U32 for conversion
   subtype Counter_Bytes is Bytes_8;     --  Use Utils.To_U64 for conversion

   subtype Public_Key_Bytes is Crypto.X25519.Public_Key;
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
   --  Message Header Sizes (Bytes)
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
   --  Uses XChaCha20Poly1305 (24-byte nonce) for cookie encryption
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
   --  Message Type 4: Transport Data (Header Only)
   ---------------------
   --
   --  The header is a fixed-size record for overlay on packet memory.
   --  Use Message_Transport_Data for full packet with Byte_Span payload.

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

   --  Full transport data message with variable-length encrypted payload.
   --  The Enc_Packet span points to the encrypted data following the header.
   --
   --  Usage:
   --    1. Overlay header on packet buffer to read fixed fields
   --    2. Create Enc_Packet span from buffer offset 16 to end
   --    3. Or use Parse_Transport_Data to construct from raw packet span
   type Message_Transport_Data is record
      Header     : Message_Transport_Header;
      Enc_Packet : Byte_Span;  --  Variable-length encrypted payload
   end record;

   --  Parse a raw packet span into a transport data message.
   --  Returns the header fields and a span pointing to the encrypted payload.
   --  Precondition ensures packet is at least header size.
   function Parse_Transport_Data
     (Packet : Byte_Span) return Message_Transport_Data
   with Pre => Length (Packet) >= Transport_Header_Size;

   ---------------------
   --  Message Kind Detection
   ---------------------

   type Message_Kind is
     (Kind_Handshake_Initiation,
      Kind_Handshake_Response,
      Kind_Cookie_Reply,
      Kind_Transport_Data,
      Kind_Unknown);

   function Get_Message_Kind (Type_Byte : Unsigned_8) return Message_Kind;

end Transport;
