--  Transport - WireGuard Transport Layer Implementation

package body Transport
  with SPARK_Mode => Off  --  Address arithmetic requires SPARK_Mode Off
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

end Transport;
