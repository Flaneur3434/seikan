--  Transport - WireGuard Transport Layer Implementation

package body Transport
  with SPARK_Mode => On  --  Address arithmetic requires SPARK_Mode Off
is

   ---------------------
   --  Message Kind Detection
   ---------------------

   function Get_Message_Kind (Type_Byte : Unsigned_8) return Message_Kind is
   begin
      case Type_Byte is
         when Msg_Type_Handshake_Initiation =>
            return Kind_Handshake_Initiation;

         when Msg_Type_Handshake_Response   =>
            return Kind_Handshake_Response;

         when Msg_Type_Cookie_Reply         =>
            return Kind_Cookie_Reply;

         when Msg_Type_Transport_Data       =>
            return Kind_Transport_Data;

         when others                        =>
            return Kind_Unknown;
      end case;
   end Get_Message_Kind;

   ---------------------
   --  MAC1 Prefix Extraction
   ---------------------

   function To_Mac1_Prefix
     (Msg : Message_Handshake_Initiation) return Initiation_Mac1_Prefix_Bytes
   is
      Result : Initiation_Mac1_Prefix_Bytes;
      Offset : Natural := 0;
   begin
      Result (Offset) := Msg.Msg_Type;
      Offset := Offset + 1;

      Result (Offset .. Offset + 2) := Msg.Reserved;
      Offset := Offset + 3;

      Result (Offset .. Offset + 3) := Msg.Sender;
      Offset := Offset + 4;

      Result (Offset .. Offset + Key_Size - 1) :=
        Utils.Byte_Array (Msg.Ephemeral);
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
      Result : Response_Mac1_Prefix_Bytes;
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

      Result (Offset .. Offset + Key_Size - 1) :=
        Utils.Byte_Array (Msg.Ephemeral);
      Offset := Offset + Key_Size;

      Result (Offset .. Offset + Encrypted_Empty_Size - 1) :=
        Msg.Encrypted_Empty;

      return Result;
   end To_Mac1_Prefix;

   ---------------------
   --  C Interop Implementation
   ---------------------

   procedure Release_To_C
     (Handle : in out Buffer_Handle;
      Length : Packet_Length;
      Addr   : out System.Address)
   is
      Ref : Buffer_Ref;
   begin
      if Packet_Pool.Is_Null (Handle) then
         Addr := System.Null_Address;
         return;
      end if;

      --  Borrow mutably to set length and get address
      Packet_Pool.Borrow_Mut (Handle, Ref);
      Ref.Buf_Ptr.Len := Length;
      Addr := Ref.Buf_Ptr.all'Address;
      Packet_Pool.Return_Ref (Handle, Ref);

      --  Null out the handle - C now owns the buffer
      Packet_Pool.Reset_Handle (Handle);
   end Release_To_C;

   procedure Acquire_From_C
     (Addr   : System.Address;
      Handle : out Buffer_Handle;
      Length : out Packet_Length)
   is
      use System;
      View : Buffer_View;
   begin
      if Addr = Null_Address then
         Packet_Pool.Create_From_Address (Addr, Handle);
         Length := 0;
         return;
      end if;

      --  Create handle pointing to this buffer
      Packet_Pool.Create_From_Address (Addr, Handle);

      --  Read length directly
      View := Packet_Pool.Borrow (Handle);
      Length := View.Buf_Ptr.Len;
   end Acquire_From_C;

end Transport;
