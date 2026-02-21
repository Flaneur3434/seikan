--  Messages - VeriGuard Wire Protocol Message Types
--
--  VeriGuard message types with representation clauses for zero-copy
--  packet parsing. Records can be overlaid on raw packet memory using
--  Unchecked_Conversion or address overlays, similar to casting to
--  packed C structs.
--
--  All multi-byte integer fields use Byte_Array to avoid alignment
--  issues. Use Utils.To_U32/To_U64 for conversion to native integers.
--
--  Wire Format:
--    libsodium backend   -> WireGuard compatible (can debug with wg tools)
--    libhydrogen backend -> VeriGuard format (larger messages, not compatible)
--
--  Message types are defined in Messages_Wire (backend-specific).
--
--  Packet Pool:
--    This package owns the shared buffer pool for network packets.
--    Zero-copy buffer handoff between Ada and C layers via wg_packet_t.

with System;
with Interfaces; use Interfaces;
with Utils;
with Utils.Memory_Pool;
with Messages_Wire;

package Messages
  with SPARK_Mode => On
is
   ---------------------------------------------------------------------------
   --  Packet Pools - Separate RX and TX buffer pools
   --
   --  Two pools ensure RX can never starve TX and vice versa.
  --  Sized for transport data path packets.
  --  1560 gives headroom for 1500-byte class paths.
   ---------------------------------------------------------------------------

  Packet_Size : constant := 1560;
   Pool_Size   : constant := 4;

   package RX_Pool is new Utils.Memory_Pool
     (Packet_Size => Packet_Size,
      Pool_Size   => Pool_Size);

   package TX_Pool is new Utils.Memory_Pool
     (Packet_Size => Packet_Size,
      Pool_Size   => Pool_Size);

   --  Re-export commonly used types (from TX_Pool; both pools share the
   --  same generic, so the types are structurally identical)
   subtype Packet_Buffer is TX_Pool.Packet_Buffer;
   subtype Buffer_Handle is TX_Pool.Buffer_Handle;
   subtype Buffer_View is TX_Pool.Buffer_View;
   subtype Buffer_Ref is TX_Pool.Buffer_Ref;

   --  RX-specific handle type (distinct from TX for type safety)
   subtype RX_Buffer_Handle is RX_Pool.Buffer_Handle;
   subtype RX_Buffer_View is RX_Pool.Buffer_View;
   subtype RX_Buffer_Ref is RX_Pool.Buffer_Ref;

   ---------------------
   --  Message Type Constants
   ---------------------

   Msg_Type_Handshake_Initiation : constant Unsigned_8 := 1;
   Msg_Type_Handshake_Response   : constant Unsigned_8 := 2;
   Msg_Type_Cookie_Reply         : constant Unsigned_8 := 3;
   Msg_Type_Transport_Data       : constant Unsigned_8 := 4;

   ---------------------
   --  Re-export constants and types from Transport_Messages
   --  (backend-specific definitions)
   ---------------------

   --  Field sizes
   Key_Size       : constant := Messages_Wire.Key_Size;
   Hash_Size      : constant := Messages_Wire.Hash_Size;
   Aead_Tag_Size  : constant := Messages_Wire.Aead_Tag_Size;
   Cookie_Size    : constant := Messages_Wire.Cookie_Size;
   Mac_Size       : constant := Messages_Wire.Mac_Size;
   Timestamp_Size : constant := Messages_Wire.Timestamp_Size;
   XChaCha_Nonce_Size : constant := Messages_Wire.XChaCha_Nonce_Size;

   --  Encrypted field sizes
   Encrypted_Static_Size    : constant :=
     Messages_Wire.Encrypted_Static_Size;
   Encrypted_Timestamp_Size : constant :=
     Messages_Wire.Encrypted_Timestamp_Size;
   Encrypted_Empty_Size     : constant :=
     Messages_Wire.Encrypted_Empty_Size;
   Encrypted_Cookie_Size    : constant :=
     Messages_Wire.Encrypted_Cookie_Size;

   --  Message sizes
   Handshake_Init_Size     : constant :=
     Messages_Wire.Handshake_Init_Size;
   Handshake_Response_Size : constant :=
     Messages_Wire.Handshake_Response_Size;
   Cookie_Reply_Size       : constant :=
     Messages_Wire.Cookie_Reply_Size;
   Transport_Header_Size   : constant :=
     Messages_Wire.Transport_Header_Size;

   ---------------------
   --  Byte Array Subtypes (re-exported)
   ---------------------

   subtype Reserved_Bytes is Messages_Wire.Reserved_Bytes;
   subtype Sender_Bytes is Messages_Wire.Sender_Bytes;
   subtype Receiver_Bytes is Messages_Wire.Receiver_Bytes;
   subtype Counter_Bytes is Messages_Wire.Counter_Bytes;

   subtype Public_Key_Bytes is Messages_Wire.Public_Key_Bytes;
   subtype Mac_Bytes is Messages_Wire.Mac_Bytes;
   subtype XChaCha_Nonce_Bytes is Messages_Wire.XChaCha_Nonce_Bytes;

   subtype Encrypted_Static_Bytes is
     Messages_Wire.Encrypted_Static_Bytes;
   subtype Encrypted_Timestamp_Bytes is
     Messages_Wire.Encrypted_Timestamp_Bytes;
   subtype Encrypted_Empty_Bytes is
     Messages_Wire.Encrypted_Empty_Bytes;
   subtype Encrypted_Cookie_Bytes is
     Messages_Wire.Encrypted_Cookie_Bytes;

   ---------------------
   --  Message Types (re-exported from backend-specific package)
   ---------------------

   subtype Message_Handshake_Initiation is
     Messages_Wire.Message_Handshake_Initiation;

   subtype Message_Handshake_Response is
     Messages_Wire.Message_Handshake_Response;

   subtype Message_Cookie_Reply is
     Messages_Wire.Message_Cookie_Reply;

   subtype Message_Transport_Header is
     Messages_Wire.Message_Transport_Header;

   ---------------------
   --  MAC1 Prefix Types
   --
   --  MAC1 is computed over all message bytes preceding the Mac1 field.
   --  These are defined here (not in Transport_Messages) because the
   --  computation is backend-independent — it uses only the shared
   --  field-size constants and message record types.
   ---------------------

   --  Byte offsets of the Mac1 field within each message
   Mac1_Initiation_Offset : constant :=
     1 + 3 + 4 + Key_Size + Encrypted_Static_Size + Encrypted_Timestamp_Size;

   Mac1_Response_Offset : constant :=
     1 + 3 + 4 + 4 + Key_Size + Encrypted_Empty_Size;

   subtype Initiation_Mac1_Prefix_Bytes is
     Utils.Byte_Array (0 .. Mac1_Initiation_Offset - 1);
   subtype Response_Mac1_Prefix_Bytes is
     Utils.Byte_Array (0 .. Mac1_Response_Offset - 1);

   --  Extract the bytes preceding Mac1 from a handshake initiation message.
   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation)
      return Initiation_Mac1_Prefix_Bytes
   with Global => null;

   --  Extract the bytes preceding Mac1 from a handshake response message.
   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response)
      return Response_Mac1_Prefix_Bytes
   with Global => null;

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

   ---------------------
   --  C Interop - Packet Buffer Transfers
   --
   --  Zero-copy buffer handoff between Ada and C layers.
   --  These operations transfer ownership - after Release_To_C,
   --  the Ada handle is null; after Acquire_From_C, Ada owns the buffer.
   ---------------------

   --  Packet length type (matches uint16_t in C struct)
   subtype Packet_Length is Unsigned_16;

   --  Release TX buffer to C layer for transmission.
   --  Handle becomes null; C now owns the buffer.
   --  Returns address of wg_packet_t for C to use.
   procedure Release_TX_To_C
     (Handle : in out Buffer_Handle;
      Length : Packet_Length;
      Addr   : out System.Address)
     with SPARK_Mode => Off;

   --  Acquire RX buffer from C layer after reception.
   --  Takes ownership; C must not use the buffer after this.
   --  Length contains valid data length from C.
   procedure Acquire_RX_From_C
     (Addr   : System.Address;
      Handle : out RX_Buffer_Handle;
      Length : out Packet_Length)
     with SPARK_Mode => Off;

   --  Release RX buffer back to C layer (no-copy netif RX path).
   --  Called by Handle_Transport_RX_Netif after in-place decryption.
   --  Ada gives up ownership; C wraps the buffer in a pbuf_custom for
   --  zero-copy injection into lwIP.  Handle becomes null after call.
   procedure Release_RX_To_C
     (Handle : in out RX_Buffer_Handle;
      Addr   : out System.Address)
     with SPARK_Mode => Off;

   --  Note: Access buffer fields directly via Borrow/Borrow_Mut:
   --    View := TX_Pool.Borrow (Handle);
   --    Len := View.Buf_Ptr.Len;
   --
   --    TX_Pool.Borrow_Mut (Handle, Ref);
   --    Ref.Buf_Ptr.Len := New_Length;
   --    TX_Pool.Return_Ref (Handle, Ref);

end Messages;
