--  Transport - WireGuard Transport Data Protocol (Type 4 Messages)
--
--  Handles encryption and decryption of data packets after a session
--  has been established by the Noise IKpsk2 handshake.
--
--  TX Path (encrypt):
--    1. Caller provides plaintext IP packet
--    2. Build transport header (type=4, receiver index, counter)
--    3. Encrypt payload in-place with ChaCha20-Poly1305
--    4. Increment nonce counter
--
--  RX Path (decrypt):
--    1. Parse transport header, extract receiver index + counter
--    2. Validate counter (anti-replay window)
--    3. Decrypt payload in-place with ChaCha20-Poly1305
--    4. Return plaintext IP packet
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
with Handshake;
with Messages;

package Transport
  with SPARK_Mode => On
is
   use type Handshake.Handshake_State_Kind;

   ---------------------------------------------------------------------------
   --  Session Key Material
   --
   --  Derived from the handshake: two symmetric keys (one for each
   --  direction) plus the receiver index assigned by the peer.
   ---------------------------------------------------------------------------

   subtype Session_Key is Crypto.AEAD.Key_Buffer;

   type Session is record
      Send_Key       : Session_Key;
      Receive_Key    : Session_Key;
      Sender_Index   : Unsigned_32;
      Receiver_Index : Unsigned_32;
      Send_Counter   : Unsigned_64;
      Valid          : Boolean;
   end record;

   Null_Session : constant Session :=
     (Send_Key       => (others => 0),
      Receive_Key    => (others => 0),
      Sender_Index   => 0,
      Receiver_Index => 0,
      Send_Counter   => 0,
      Valid          => False);

   ---------------------------------------------------------------------------
   --  Init_Session - Derive transport keys from handshake chaining key
   --
   --  Called after a successful handshake to derive the symmetric session
   --  keys for transport data encryption/decryption.  Securely wipes all
   --  ephemeral handshake material (forward secrecy).
   --
   --  From the WireGuard whitepaper:
   --    (T_send, T_recv) := KDF2(C, "")
   --    Epriv_i = Epub_i = Epriv_r = Epub_r = C_i = C_r := ε
   --
   --  The initiator sends on τ1 and receives on τ2;
   --  the responder sends on τ2 and receives on τ1.
   ---------------------------------------------------------------------------

   procedure Init_Session
     (S              : out Session;
      HS             : in out Handshake.Handshake_State;
      Result         : out Status)
   with
     SPARK_Mode => Off,
     Pre  => HS.Kind = Handshake.State_Established
             or else HS.Kind = Handshake.State_Responder_Sent;

   ---------------------------------------------------------------------------
   --  Encrypt - Build and encrypt a transport data message (TX path)
   --
   --  Writes the transport header + encrypted payload into the TX buffer.
   --  Increments the session nonce counter on success.
   --
   --  Buffer must be large enough for:
   --    Header (16) + Plaintext'Length + AEAD Tag
   ---------------------------------------------------------------------------

   procedure Encrypt_Packet
     (S         : in out Session;
      Plaintext : Byte_Array;
      Packet    : out Byte_Array;
      Length    : out Unsigned_16;
      Result    : out Status)
   with
     Global => null,
     Pre    =>
       S.Valid
       and then Plaintext'Length > 0
       and then Plaintext'Length <= Utils.Max_Packet_Size
                                     - Messages.Transport_Header_Size
                                     - Crypto.AEAD.Tag_Bytes
       and then Packet'Length >= Messages.Transport_Header_Size
                                   + Plaintext'Length
                                   + Crypto.AEAD.Tag_Bytes,
     Post   =>
       (if Result = Success then
          S.Send_Counter = S.Send_Counter'Old + 1);

   ---------------------------------------------------------------------------
   --  Decrypt - Authenticate and decrypt a transport data message (RX path)
   --
   --  Decrypts the payload in-place within Packet.  On success the
   --  plaintext occupies:
   --    Packet (Packet'First + Header .. Packet'First + Header + Length - 1)
   --
   --  Does NOT do replay-window checking here; that belongs in the
   --  session state machine.
   ---------------------------------------------------------------------------

   procedure Decrypt_Packet
     (S       : Session;
      Packet  : in out Byte_Array;
      Length  : out Unsigned_16;
      Counter : out Unsigned_64;
      Result  : out Status)
   with
     Global => null,
     Pre    =>
       S.Valid
       and then Packet'Length <= Utils.Max_Packet_Size
       and then Packet'Length > Messages.Transport_Header_Size
                                  + Crypto.AEAD.Tag_Bytes;

end Transport;
