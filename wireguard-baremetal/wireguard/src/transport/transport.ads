--  Transport - WireGuard Transport Data Protocol (Type 4 Messages)
--
--  Stateless encryption/decryption of data packets using session keys
--  established by the Noise IKpsk2 handshake.
--
--  Session state (keys, counters, replay) is managed by the Session
--  module.  Transport is a pure crypto module — no mutable state.
--
--  TX Path (encrypt):
--    1. Caller provides plaintext, key, receiver index, and nonce counter
--    2. Build transport header (type=4, receiver index, counter)
--    3. Encrypt payload in-place with ChaCha20-Poly1305
--    4. Return the complete packet
--
--  RX Path (decrypt):
--    1. Parse transport header, extract receiver index + counter
--    2. Decrypt payload in-place with ChaCha20-Poly1305
--    3. Return plaintext length and counter (caller does replay check)
--
--  Wire format (from Messages_Wire.Message_Transport_Header):
--    [0]      msg_type  = 4
--    [1..3]   reserved  = 0
--    [4..7]   receiver  = peer's sender index (little-endian)
--    [8..15]  counter   = nonce counter (little-endian)
--    [16..]   encrypted payload + AEAD tag

with Interfaces; use Interfaces;
with Utils;      use Utils;
with Crypto.AEAD;
with Messages;

package Transport
  with SPARK_Mode => On
is

   --  Maximum plaintext payload that fits in a transport packet:
   --    Max_Packet_Size - Header (16) - AEAD Tag
   Max_Payload : constant Natural :=
     Utils.Max_Packet_Size
     - Messages.Transport_Header_Size
     - Crypto.AEAD.Tag_Bytes;

   ---------------------------------------------------------------------------
   --  Encrypt_Packet - Build and encrypt a transport data message (TX path)
   --
   --  Writes the transport header + encrypted payload into the output
   --  buffer.  Purely functional — does not modify any session state.
   --  The caller is responsible for incrementing the nonce counter.
   --
   --  Buffer must be large enough for:
   --    Header (16) + Plaintext'Length + AEAD Tag
   ---------------------------------------------------------------------------

   procedure Encrypt_Packet
     (Key            : Crypto.AEAD.Key_Buffer;
      Receiver_Index : Unsigned_32;
      Counter        : Unsigned_64;
      Plaintext      : Byte_Array;
      Packet         : out Byte_Array;
      Length         : out Unsigned_16;
      Result         : out Status)
   with
     Global => null,
     Pre    =>
       Packet'Length <= Utils.Max_Packet_Size --  give GNATprove a hard ceiling
       and then
         Plaintext'Length in 0 .. Max_Payload --  0 = keepalive (empty payload)
       and then
         --  Make sure payload can fit into packet buffer
         Plaintext'Length
         <= Packet'Length
            - (Messages.Transport_Header_Size + Crypto.AEAD.Tag_Bytes),
     Post   => (if Result = Success then Length > 0);

   ---------------------------------------------------------------------------
   --  Decrypt_Packet - Authenticate and decrypt a transport data message
   --
   --  Decrypts the payload in-place within Packet.  On success the
   --  plaintext occupies:
   --    Packet (Packet'First + Header .. Packet'First + Header + Length - 1)
   --
   --  Returns the counter from the packet header for the caller to
   --  validate against the replay window.
   ---------------------------------------------------------------------------

   ---------------------------------------------------------------------------
   --  Encrypt_Into_Buffer - Zero-copy encrypt into a TX pool buffer
   --
   --  Wraps Encrypt_Packet with an address overlay so the ciphertext
   --  is written directly into the pool buffer's Data array.
   --  Global => null tells SPARK the body has no side effects on
   --  abstract state (the overlay is SPARK_Mode => Off internally).
   ---------------------------------------------------------------------------

   procedure Encrypt_Into_Buffer
     (Ref            : Messages.Buffer_Ref;
      Key            : Crypto.AEAD.Key_Buffer;
      Receiver_Index : Unsigned_32;
      Counter        : Unsigned_64;
      Plaintext      : Byte_Array;
      Length         : out Unsigned_16;
      Result         : out Status)
   with
     Global => null,
     Pre    => Plaintext'Length in 0 .. Max_Payload,
     Post   => (if Result = Success then Length > 0);

   ---------------------------------------------------------------------------
   --  Decrypt_In_Buffer - Zero-copy decrypt in an RX pool buffer
   --
   --  Wraps Decrypt_Packet with an address overlay so the decryption
   --  operates directly on the pool buffer's Data array.
   --  Global => null tells SPARK the body has no side effects on
   --  abstract state (the overlay is SPARK_Mode => Off internally).
   ---------------------------------------------------------------------------

   procedure Decrypt_In_Buffer
     (Ref       : Messages.RX_Buffer_Ref;
      RX_Length : Unsigned_16;
      Key       : Crypto.AEAD.Key_Buffer;
      Length    : out Unsigned_16;
      Counter   : out Unsigned_64;
      Result    : out Status)
   with
     Global => null,
     Pre    =>
       Natural (RX_Length) <= Utils.Max_Packet_Size
       and then
         Natural (RX_Length)
         >= Messages.Transport_Header_Size + Crypto.AEAD.Tag_Bytes;

end Transport;
