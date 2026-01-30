with System;

generic
   Packet_Size : Positive;
   Pool_Size   : Positive;
package Utils.Memory_Pool
   with SPARK_Mode    => On,
        Abstract_State => Pool_State
is
   subtype Pool_Index is Natural range 0 .. Pool_Size - 1;

   type Packet_Buffer is new Byte_Array (0 .. Packet_Size - 1);
   --  Align for DMA transfers
   for Packet_Buffer'Alignment use 16;

   type Buffer_Descriptor is record
      Idx     : Pool_Index;
      Address : System.Address;
      In_Use  : Boolean;
   end record;

   Null_Descriptor : constant Buffer_Descriptor :=
     (Idx     => 0,
      Address => System.Null_Address,
      In_Use  => False);

   procedure Initialize
   with Global => (Output => Pool_State);

   procedure Allocate (Desc : out Buffer_Descriptor)
   with Global => (In_Out => Pool_State);

   procedure Free (Desc : in out Buffer_Descriptor)
   with Global => (In_Out => Pool_State),
        Pre    => Desc.In_Use,
        Post   => not Desc.In_Use;

   function Get_Buffer (Desc : Buffer_Descriptor) return Packet_Buffer
   with Global => (Input => Pool_State),
        Pre    => Desc.In_Use;

   procedure Set_Buffer (Desc : Buffer_Descriptor; Data : Packet_Buffer)
   with Global => (In_Out => Pool_State),
        Pre    => Desc.In_Use;

   function Get_Address (Desc : Buffer_Descriptor) return System.Address
   with Global => (Input => Pool_State),
        Pre    => Desc.In_Use;

end Utils.Memory_Pool;
