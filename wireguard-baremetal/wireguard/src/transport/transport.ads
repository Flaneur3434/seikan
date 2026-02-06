--  Transport - VeriGuard Transport Layer
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
--  Message types are defined in Transport_Messages (backend-specific).
--
--  Packet Pool:
--    This package owns the shared buffer pool for network packets.
--    Zero-copy buffer handoff between Ada and C layers via wg_packet_t.

with System;
with Interfaces; use Interfaces;
with Utils;
with Utils.Memory_Pool;
with Transport_Messages;

package Transport
  with SPARK_Mode => On
is
   ---------------------------------------------------------------------------
   --  Packet Pool - Shared buffer pool for network packets
   --
   --  Used by both Ada code and C FFI. Instantiated here in Transport
   --  so all protocol modules can access it.
   ---------------------------------------------------------------------------

   Packet_Size : constant := Utils.Max_Packet_Size;
   Pool_Size   : constant := 8;

   package Packet_Pool is new Utils.Memory_Pool
     (Packet_Size => Packet_Size,
      Pool_Size   => Pool_Size);

   --  Re-export commonly used types
   subtype Packet_Buffer is Packet_Pool.Packet_Buffer;
   subtype Buffer_Handle is Packet_Pool.Buffer_Handle;
   subtype Buffer_View is Packet_Pool.Buffer_View;
   subtype Buffer_Ref is Packet_Pool.Buffer_Ref;

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
   Key_Size       : constant := Transport_Messages.Key_Size;
   Hash_Size      : constant := Transport_Messages.Hash_Size;
   Aead_Tag_Size  : constant := Transport_Messages.Aead_Tag_Size;
   Cookie_Size    : constant := Transport_Messages.Cookie_Size;
   Mac_Size       : constant := Transport_Messages.Mac_Size;
   Timestamp_Size : constant := Transport_Messages.Timestamp_Size;
   XChaCha_Nonce_Size : constant := Transport_Messages.XChaCha_Nonce_Size;

   --  Encrypted field sizes
   Encrypted_Static_Size    : constant :=
     Transport_Messages.Encrypted_Static_Size;
   Encrypted_Timestamp_Size : constant :=
     Transport_Messages.Encrypted_Timestamp_Size;
   Encrypted_Empty_Size     : constant :=
     Transport_Messages.Encrypted_Empty_Size;
   Encrypted_Cookie_Size    : constant :=
     Transport_Messages.Encrypted_Cookie_Size;

   --  Message sizes
   Handshake_Init_Size     : constant :=
     Transport_Messages.Handshake_Init_Size;
   Handshake_Response_Size : constant :=
     Transport_Messages.Handshake_Response_Size;
   Cookie_Reply_Size       : constant :=
     Transport_Messages.Cookie_Reply_Size;
   Transport_Header_Size   : constant :=
     Transport_Messages.Transport_Header_Size;

   ---------------------
   --  Byte Array Subtypes (re-exported)
   ---------------------

   subtype Reserved_Bytes is Transport_Messages.Reserved_Bytes;
   subtype Sender_Bytes is Transport_Messages.Sender_Bytes;
   subtype Receiver_Bytes is Transport_Messages.Receiver_Bytes;
   subtype Counter_Bytes is Transport_Messages.Counter_Bytes;

   subtype Public_Key_Bytes is Transport_Messages.Public_Key_Bytes;
   subtype Mac_Bytes is Transport_Messages.Mac_Bytes;
   subtype XChaCha_Nonce_Bytes is Transport_Messages.XChaCha_Nonce_Bytes;

   subtype Encrypted_Static_Bytes is
     Transport_Messages.Encrypted_Static_Bytes;
   subtype Encrypted_Timestamp_Bytes is
     Transport_Messages.Encrypted_Timestamp_Bytes;
   subtype Encrypted_Empty_Bytes is
     Transport_Messages.Encrypted_Empty_Bytes;
   subtype Encrypted_Cookie_Bytes is
     Transport_Messages.Encrypted_Cookie_Bytes;

   ---------------------
   --  Message Types (re-exported from backend-specific package)
   ---------------------

   subtype Message_Handshake_Initiation is
     Transport_Messages.Message_Handshake_Initiation;

   subtype Message_Handshake_Response is
     Transport_Messages.Message_Handshake_Response;

   subtype Message_Cookie_Reply is
     Transport_Messages.Message_Cookie_Reply;

   subtype Message_Transport_Header is
     Transport_Messages.Message_Transport_Header;

   ---------------------
   --  MAC1 Prefix Types (re-exported from backend-specific package)
   ---------------------

   Mac1_Initiation_Offset : constant :=
     Transport_Messages.Mac1_Initiation_Offset;
   Mac1_Response_Offset : constant :=
     Transport_Messages.Mac1_Response_Offset;

   subtype Initiation_Mac1_Prefix_Bytes is
     Transport_Messages.Initiation_Mac1_Prefix_Bytes;
   subtype Response_Mac1_Prefix_Bytes is
     Transport_Messages.Response_Mac1_Prefix_Bytes;

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation)
      return Initiation_Mac1_Prefix_Bytes
      renames Transport_Messages.To_Mac1_Prefix;

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response)
      return Response_Mac1_Prefix_Bytes
      renames Transport_Messages.To_Mac1_Prefix;

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

   --  Release buffer to C layer for transmission
   --  Handle becomes null; C now owns the buffer.
   --  Returns address of wg_packet_t for C to use.
   procedure Release_To_C
     (Handle : in out Buffer_Handle;
      Length : Packet_Length;
      Addr   : out System.Address);

   --  Acquire buffer from C layer after reception
   --  Takes ownership; C must not use the buffer after this.
   --  Length contains valid data length from C.
   procedure Acquire_From_C
     (Addr   : System.Address;
      Handle : out Buffer_Handle;
      Length : out Packet_Length);

   --  Note: Access buffer fields directly via Borrow/Borrow_Mut:
   --    View := Packet_Pool.Borrow (Handle);
   --    Len := View.Buf_Ptr.Len;
   --
   --    Packet_Pool.Borrow_Mut (Handle, Ref);
   --    Ref.Buf_Ptr.Len := New_Length;
   --    Ref.Buf_Ptr.Offset := New_Offset;
   --    Packet_Pool.Return_Ref (Handle, Ref);

end Transport;
