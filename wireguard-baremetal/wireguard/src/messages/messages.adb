--  Messages - WireGuard Wire Protocol Message Types Implementation

with Ada.Unchecked_Conversion;
with Utils;

package body Messages
  with SPARK_Mode => On
is

   use Utils;

   ---------------------
   --  MAC1 Prefix Extraction
   ---------------------

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation) return Initiation_Mac1_Prefix_Bytes
   is
      Result : Initiation_Mac1_Prefix_Bytes := [others => 0];
      Offset : Natural := 0;
   begin
      Result (Offset) := Msg.Msg_Type;
      Offset := Offset + 1;

      Result (Offset .. Offset + 2) := Msg.Reserved;
      Offset := Offset + 3;

      Result (Offset .. Offset + 3) := Msg.Sender;
      Offset := Offset + 4;

      Result (Offset .. Offset + Key_Size - 1) := Byte_Array (Msg.Ephemeral);
      Offset := Offset + Key_Size;

      Result (Offset .. Offset + Encrypted_Static_Size - 1) :=
        Msg.Encrypted_Static;
      Offset := Offset + Encrypted_Static_Size;

      Result (Offset .. Offset + Encrypted_Timestamp_Size - 1) :=
        Msg.Encrypted_Timestamp;

      return Result;
   end To_Mac1_Prefix;

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Response) return Response_Mac1_Prefix_Bytes
   is
      Result : Response_Mac1_Prefix_Bytes := [others => 0];
      Offset : Natural := 0;
   begin
      Result (Offset) := Msg.Msg_Type;
      Offset := Offset + 1;

      Result (Offset .. Offset + 2) := Msg.Reserved;
      Offset := Offset + 3;

      Result (Offset .. Offset + 3) := Msg.Sender;
      Offset := Offset + 4;

      Result (Offset .. Offset + 3) := Msg.Receiver;
      Offset := Offset + 4;

      Result (Offset .. Offset + Key_Size - 1) := Byte_Array (Msg.Ephemeral);
      Offset := Offset + Key_Size;

      Result (Offset .. Offset + Encrypted_Empty_Size - 1) :=
        Msg.Encrypted_Empty;

      return Result;
   end To_Mac1_Prefix;

   ---------------------
   --  C Interop Implementation
   ---------------------

   procedure Release_TX_To_C
     (Handle : in out Buffer_Handle;
      Length : Packet_Length;
      Ptr    : out Utils.C_Buffer_Ptr)
   is
      Ref : Buffer_Ref;
   begin
      --  Borrow mutably to set length
      TX_Pool.Borrow_Mut (Handle, Ref);
      declare
         P : constant TX_Pool.Buffer_Ptr := TX_Pool.Get_Ptr (Ref);
      begin
         P.Len := Length;
      end;
      TX_Pool.Return_Ref (Handle, Ref);

      --  Extract C pointer, then release ownership to C
      Ptr := TX_Pool.To_C_Ptr (Handle);
      TX_Pool.Reset_Handle (Handle);
   end Release_TX_To_C;

   procedure Acquire_RX_From_C
     (Ptr    : Utils.C_Buffer_Ptr;
      Handle : out RX_Buffer_Handle;
      Length : out Packet_Length)
   is
      View : RX_Buffer_View;
   begin
      --  Create handle from C pointer (takes ownership)
      RX_Pool.From_C_Ptr (Ptr, Handle);

      --  Read length directly
      View := RX_Pool.Borrow (Handle);
      Length := View.Buf_Ptr.Len;
   end Acquire_RX_From_C;

   procedure Release_RX_To_C
     (Handle : in out RX_Buffer_Handle; Ptr : out Utils.C_Buffer_Ptr) is
   begin
      --  Extract C pointer, then release ownership to C
      Ptr := RX_Pool.To_C_Ptr (Handle);
      RX_Pool.Reset_Handle (Handle);
   end Release_RX_To_C;

   ---------------------
   --  Buffer ↔ Message Conversions
   --
   --  Bodies are SPARK_Mode => Off (Unchecked_Conversion).
   --  Specs are SPARK-visible so callers are provable.
   --  Safe because all fields are Unsigned_8 or Byte_Array — every
   --  bit pattern is valid.
   ---------------------

   function Read_Initiation
     (View : RX_Buffer_View) return Message_Handshake_Initiation
   with SPARK_Mode => Off
   is
      subtype Src is Byte_Array (0 .. Handshake_Init_Size - 1);
      function Convert is new
        Ada.Unchecked_Conversion (Src, Message_Handshake_Initiation);
   begin
      return Convert (Byte_Array (View.Buf_Ptr.Data) (Src'Range));
   end Read_Initiation;

   function Read_Response
     (View : RX_Buffer_View) return Message_Handshake_Response
   with SPARK_Mode => Off
   is
      subtype Src is Byte_Array (0 .. Handshake_Response_Size - 1);
      function Convert is new
        Ada.Unchecked_Conversion (Src, Message_Handshake_Response);
   begin
      return Convert (Byte_Array (View.Buf_Ptr.Data) (Src'Range));
   end Read_Response;

   function Read_Undefined (View : RX_Buffer_View) return Undefined_Message
   with SPARK_Mode => Off
   is
      subtype Src is Byte_Array (0 .. 3);
      function Convert is new
        Ada.Unchecked_Conversion (Src, Undefined_Message);
   begin
      return Convert (Byte_Array (View.Buf_Ptr.Data) (Src'Range));
   end Read_Undefined;

   procedure Write_Initiation
     (Ref : Buffer_Ref; Msg : Message_Handshake_Initiation)
   with SPARK_Mode => Off
   is
      subtype Dst is Byte_Array (0 .. Handshake_Init_Size - 1);
      function Convert is new
        Ada.Unchecked_Conversion (Message_Handshake_Initiation, Dst);
      Bytes : constant Dst := Convert (Msg);
   begin
      for I in Bytes'Range loop
         TX_Pool.Get_Ptr (Ref).Data (I) := Bytes (I);
      end loop;
   end Write_Initiation;

   procedure Write_Response
     (Ref : Buffer_Ref; Msg : Message_Handshake_Response)
   with SPARK_Mode => Off
   is
      subtype Dst is Byte_Array (0 .. Handshake_Response_Size - 1);
      function Convert is new
        Ada.Unchecked_Conversion (Message_Handshake_Response, Dst);
      Bytes : constant Dst := Convert (Msg);
   begin
      for I in Bytes'Range loop
         TX_Pool.Get_Ptr (Ref).Data (I) := Bytes (I);
      end loop;
   end Write_Response;

end Messages;
