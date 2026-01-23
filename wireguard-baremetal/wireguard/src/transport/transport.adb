--  Transport - WireGuard Transport Layer Implementation

with System.Storage_Elements;

package body Transport
  with SPARK_Mode => Off  --  Address arithmetic requires SPARK_Mode Off
is
   use System.Storage_Elements;

   ---------------------
   --  Transport Data Parsing
   ---------------------

   function Parse_Transport_Data
     (Packet : Byte_Span) return Message_Transport_Data
   is
      --  Overlay header at packet start
      Header : Message_Transport_Header
        with Address => Data (Packet), Import;

      --  Calculate payload span (everything after header)
      Payload_Len : constant Natural :=
        Length (Packet) - Transport_Header_Size;
   begin
      return
        (Header     => Header,
         Enc_Packet => Slice_From (Packet, Transport_Header_Size));
   end Parse_Transport_Data;

   ---------------------
   --  Message Kind Detection
   ---------------------

   function Get_Message_Kind (Type_Byte : Unsigned_8) return Message_Kind is
   begin
      case Type_Byte is
         when Msg_Type_Handshake_Initiation =>
            return Kind_Handshake_Initiation;
         when Msg_Type_Handshake_Response =>
            return Kind_Handshake_Response;
         when Msg_Type_Cookie_Reply =>
            return Kind_Cookie_Reply;
         when Msg_Type_Transport_Data =>
            return Kind_Transport_Data;
         when others =>
            return Kind_Unknown;
      end case;
   end Get_Message_Kind;

end Transport;
