with System;

generic
   Packet_Size : Positive;
   Pool_Size   : Positive;
package Utils.Memory_Pool
   with SPARK_Mode     => On,
        Abstract_State => Pool_State
is
   pragma Unevaluated_Use_Of_Old (Allow);

   subtype Pool_Index is Natural range 0 .. Pool_Size - 1;
   subtype Valid_Count is Natural range 0 .. Pool_Size;

   type Packet_Buffer is new Byte_Array (0 .. Packet_Size - 1);
   for Packet_Buffer'Alignment use 16;  --  Align for DMA transfers

   ---------------------------------------------------------------------------
   --  Buffer Handle - Owns access to a buffer
   --
   --  This is a private type with SPARK ownership semantics:
   --    - Assignment moves ownership (source becomes invalid)
   --    - No copying/aliasing possible
   --    - Must be explicitly freed or moved before going out of scope
   --
   --  The full view (access type) is hidden from SPARK, but ownership
   --  checking is enforced via the Ownership annotation.
   ---------------------------------------------------------------------------

   type Buffer_Handle is private
     with Default_Initial_Condition => Is_Null (Buffer_Handle),
          Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Null (H : Buffer_Handle) return Boolean
     with Global => null,
          Annotate => (GNATprove, Ownership, "Is_Reclaimed");
   --  True if handle doesn't own a buffer

   ---------------------------------------------------------------------------
   --  Ghost Functions for Specification
   ---------------------------------------------------------------------------

   function Free_Count return Valid_Count
     with Ghost, Global => Pool_State;
   --  Number of free buffers available

   ---------------------------------------------------------------------------
   --  Pool Operations
   ---------------------------------------------------------------------------

   procedure Initialize
     with Global => (Output => Pool_State),
          Post   => Free_Count = Pool_Size;
   --  Initialize the pool. All buffers become available.

   procedure Allocate (Handle : out Buffer_Handle)
     with Global => (In_Out => Pool_State),
          Post   => (if not Is_Null (Handle)
                     then Free_Count = Free_Count'Old - 1
                     else Free_Count = Free_Count'Old);
   --  Allocate a buffer. Handle is null if pool exhausted.

   procedure Free (Handle : in out Buffer_Handle)
     with Global => (In_Out => Pool_State),
          Pre    => not Is_Null (Handle),
          Post   => Is_Null (Handle)
                    and then Free_Count = Free_Count'Old + 1;
   --  Return buffer to pool. Handle becomes null.

   function Data (Handle : Buffer_Handle) return System.Address
     with Global => null,
          Pre    => not Is_Null (Handle);
   --  Get address of valid buffer data for direct read/write access.

   ---------------------------------------------------------------------------
   --  C FFI Operations
   ---------------------------------------------------------------------------

   function C_Allocate return System.Address
     with Global => (In_Out => Pool_State),
          SPARK_Mode => Off;
   --  Allocate and return buffer address (null if exhausted)

   procedure C_Free (Buf_Addr : System.Address)
     with Global => (In_Out => Pool_State),
          SPARK_Mode => Off;
   --  Free by address

private
   pragma SPARK_Mode (Off);

   --  Buffer record: index for O(1) free + aligned data
   subtype Buffer_Index is Integer range -1 .. Pool_Size - 1;
   Null_Index : constant Buffer_Index := -1;

   type Buffer is record
      Index : Buffer_Index := Null_Index;
      Data  : aliased Packet_Buffer;
   end record
     with Convention => C;

   type Buffer_Handle is access all Buffer;

   function Is_Null (H : Buffer_Handle) return Boolean is
     (H = null or else H.Index = Null_Index);

end Utils.Memory_Pool;
