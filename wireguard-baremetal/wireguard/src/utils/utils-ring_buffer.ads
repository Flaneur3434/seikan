generic
   Capacity : Positive;
package Utils.Ring_Buffer
   with SPARK_Mode      => On,
        Abstract_State  => Buffer_State
is
   --  Ensure ringbuffer capacity is a multiple of 2
   pragma Assert ((Unsigned_32 (Capacity) and Unsigned_32 (Capacity - 1)) = 0);

   subtype Ring_Buffer_Idx is Natural range 0 .. Capacity - 1;
   subtype Ring_Buffer_Count is Natural range 0 .. Capacity - 1;

   subtype Aligned_Byte_Array is Byte_Array (Ring_Buffer_Count);

   procedure Initialize
   with Global => (Output => Buffer_State),
        Post   => Is_Empty;

   function Is_Empty return Boolean
   with Global => (Input => Buffer_State);

   function Used return Natural
   with Global => (Input => Buffer_State);

   procedure Allocate (Src : Byte_Array)
   with Global => (In_Out => Buffer_State),
        Pre    => Src'Length <= Capacity;

   procedure Free (Count : Ring_Buffer_Count)
   with Global => (In_Out => Buffer_State);

   procedure Flush (Dest : out Byte_Array)
   with Global => (In_Out => Buffer_State),
        Pre    => Dest'Length >= Used;

private
   subtype Mask_Type is Unsigned_32;
   Index_Mask : constant Mask_Type := Mask_Type (Capacity - 1);

end Utils.Ring_Buffer;
