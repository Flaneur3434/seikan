package body Utils.Ring_Buffer
   with SPARK_Mode     => On,
        Refined_State  => (Buffer_State => Ring_Buffer_Instance)
is
   type Ring_Buffer is record
      Head_Idx    : Ring_Buffer_Idx;
      Tail_Idx    : Ring_Buffer_Idx;
      Memory_Pool : Aligned_Byte_Array;
   end record;

   Ring_Buffer_Instance : Ring_Buffer;

   procedure Initialize is
   begin
      Ring_Buffer_Instance.Head_Idx := 0;
      Ring_Buffer_Instance.Tail_Idx := 0;
      Ring_Buffer_Instance.Memory_Pool := [others => 0];
   end Initialize;

   function Is_Empty return Boolean is
     (Ring_Buffer_Instance.Head_Idx = Ring_Buffer_Instance.Tail_Idx);

   function Used return Natural is
      Head : constant Natural := Ring_Buffer_Instance.Head_Idx;
      Tail : constant Natural := Ring_Buffer_Instance.Tail_Idx;
   begin
      if Head >= Tail then
         return Head - Tail;
      else
         return Capacity - Tail + Head;
      end if;
   end Used;

   procedure Allocate (Src : Byte_Array) is
      Head_Idx         : constant Ring_Buffer_Idx :=
        Ring_Buffer_Instance.Head_Idx;
      Space_To_End     : constant Natural := Capacity - Head_Idx;
      Bytes_After_Wrap : Natural;
   begin
      --  No wrap around needed
      if Src'Length <= Space_To_End then
         Ring_Buffer_Instance.Memory_Pool
           (Head_Idx .. Head_Idx + Src'Length - 1) :=
           Src;

         --  Update head with masking
         Ring_Buffer_Instance.Head_Idx :=
           Ring_Buffer_Idx
             (Mask_Type (Head_Idx + Src'Length) and Index_Mask);
         return;
      end if;

      --  First chunk: fill to end of buffer
      Ring_Buffer_Instance.Memory_Pool (Head_Idx .. Capacity - 1) :=
        Src (Src'First .. Src'First + Space_To_End - 1);

      --  Second chunk: wrap around to beginning
      Bytes_After_Wrap := Src'Length - Space_To_End;
      Ring_Buffer_Instance.Memory_Pool (0 .. Bytes_After_Wrap - 1) :=
        Src (Src'First + Space_To_End .. Src'Last);

      --  Update head (already wrapped)
      Ring_Buffer_Instance.Head_Idx := Ring_Buffer_Idx (Bytes_After_Wrap);
   end Allocate;

   procedure Free (Count : Ring_Buffer_Count) is
      Tail_Idx : constant Ring_Buffer_Idx := Ring_Buffer_Instance.Tail_Idx;
   begin
      Ring_Buffer_Instance.Tail_Idx :=
        Ring_Buffer_Idx (Mask_Type (Tail_Idx + Count) and Index_Mask);
   end Free;

   procedure Flush (Dest : out Byte_Array) is
      Head_Idx     : constant Ring_Buffer_Idx :=
        Ring_Buffer_Instance.Head_Idx;
      Tail_Idx     : constant Ring_Buffer_Idx :=
        Ring_Buffer_Instance.Tail_Idx;
      Space_To_End : constant Natural := Capacity - Tail_Idx;
      Data_Length  : Natural;
   begin
      --  No wrap around needed (tail <= head)
      if Tail_Idx <= Head_Idx then
         Data_Length := Head_Idx - Tail_Idx;
         Dest (Dest'First .. Dest'First + Data_Length - 1) :=
           Ring_Buffer_Instance.Memory_Pool (Tail_Idx .. Head_Idx - 1);
         Free (Data_Length);
         return;
      end if;

      --  First chunk (tail to physical end of array)
      Dest (Dest'First .. Dest'First + Space_To_End - 1) :=
        Ring_Buffer_Instance.Memory_Pool (Tail_Idx .. Capacity - 1);

      --  Second chunk (physical beginning of array to head)
      Dest (Dest'First + Space_To_End ..
            Dest'First + Space_To_End + Head_Idx - 1) :=
        Ring_Buffer_Instance.Memory_Pool (0 .. Head_Idx - 1);

      Free (Space_To_End + Head_Idx);
   end Flush;
end Utils.Ring_Buffer;
