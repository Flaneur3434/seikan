--  Messages - WireGuard Wire Protocol Message Types Implementation

package body Messages
  with SPARK_Mode => On
is

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

   procedure Release_TX_To_C
     (Handle : in out Buffer_Handle;
      Length : Packet_Length;
      Addr   : out System.Address)
     with SPARK_Mode => Off
   is
      Ref : Buffer_Ref;
   begin
      if TX_Pool.Is_Null (Handle) then
         Addr := System.Null_Address;
         return;
      end if;

      --  Borrow mutably to set length and get address
      TX_Pool.Borrow_Mut (Handle, Ref);
      Ref.Buf_Ptr.Len := Length;
      Addr := Ref.Buf_Ptr.all'Address;
      TX_Pool.Return_Ref (Handle, Ref);

      --  Null out the handle - C now owns the buffer
      TX_Pool.Reset_Handle (Handle);
   end Release_TX_To_C;

   procedure Acquire_RX_From_C
     (Addr   : System.Address;
      Handle : out RX_Buffer_Handle;
      Length : out Packet_Length)
     with SPARK_Mode => Off
   is
      use System;
      View : RX_Buffer_View;
   begin
      if Addr = Null_Address then
         RX_Pool.Create_From_Address (Addr, Handle);
         Length := 0;
         return;
      end if;

      --  Create handle pointing to this buffer
      RX_Pool.Create_From_Address (Addr, Handle);

      --  Read length directly
      View := RX_Pool.Borrow (Handle);
      Length := View.Buf_Ptr.Len;
   end Acquire_RX_From_C;

   procedure Release_RX_To_C
     (Handle : in out RX_Buffer_Handle;
      Addr   : out System.Address)
     with SPARK_Mode => Off
   is
      use System;
      Ref : RX_Buffer_Ref;
   begin
      if RX_Pool.Is_Null (Handle) then
         Addr := Null_Address;
         return;
      end if;

      --  Borrow mutably just to get the address
      RX_Pool.Borrow_Mut (Handle, Ref);
      Addr := Ref.Buf_Ptr.all'Address;
      RX_Pool.Return_Ref (Handle, Ref);

      --  Null out the handle - C now owns the buffer
      RX_Pool.Reset_Handle (Handle);
   end Release_RX_To_C;

end Messages;
