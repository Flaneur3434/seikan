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
   --  This is a LIMITED private type enforcing single ownership:
   --    - Cannot be copied or assigned (use Move for ownership transfer)
   --    - Must be explicitly freed or moved before going out of scope
   --    - Supports borrowing for temporary read-only or mutable access
   --
   --  The full view (access type) is hidden from SPARK, but ownership
   --  checking is enforced via the Ownership annotation.
   ---------------------------------------------------------------------------

   type Buffer_Handle is limited private
     with Default_Initial_Condition => Is_Null (Buffer_Handle),
          Annotate => (GNATprove, Ownership, "Needs_Reclamation");

   function Is_Null (H : Buffer_Handle) return Boolean
     with Global => null,
          Annotate => (GNATprove, Ownership, "Is_Reclaimed");
   --  True if handle doesn't own a buffer

   ---------------------------------------------------------------------------
   --  Borrow Types
   --
   --  Buffer_View: Read-only access (multiple concurrent borrows allowed)
   --  Buffer_Ref:  Mutable access (exclusive - only one at a time)
   --
   --  These are non-limited because they're lightweight views.
   --  Copying a view is OK - the ownership stays with the Buffer_Handle.
   ---------------------------------------------------------------------------

   type Buffer_View is private;
   --  Read-only view into buffer data (immutable borrow)

   type Buffer_Ref is private;
   --  Mutable reference to buffer data (exclusive borrow)

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
     with Global  => (In_Out => Pool_State),
          Depends => (Pool_State =>+ Handle, Handle => null),
          Pre     => not Is_Null (Handle),
          Post    => Is_Null (Handle)
                     and then Free_Count = Free_Count'Old + 1;
   --  Return buffer to pool. Handle becomes null.

   ---------------------------------------------------------------------------
   --  Ownership Transfer
   ---------------------------------------------------------------------------

   procedure Move (From : in out Buffer_Handle; To : out Buffer_Handle)
     with Global  => null,
          Depends => (To => From, From => null),
          Pre     => not Is_Null (From),
          Post    => Is_Null (From) and then not Is_Null (To);
   --  Transfer ownership from From to To. From becomes null.

   ---------------------------------------------------------------------------
   --  Borrowing Operations
   --
   --  Borrows provide temporary access without transferring ownership.
   --  The borrow is valid only while the returned view/ref is in scope.
   ---------------------------------------------------------------------------

   function Borrow (Handle : Buffer_Handle) return Buffer_View
     with Global => null,
          Pre    => not Is_Null (Handle);
   --  Borrow read-only access to buffer data.
   --  Multiple concurrent read borrows are safe.

   procedure Borrow_Mut
     (Handle : in out Buffer_Handle;
      Ref    : out Buffer_Ref)
     with Global => null,
          Pre    => not Is_Null (Handle),
          Post   => not Is_Null (Handle);
   --  Borrow exclusive mutable access to buffer data.
   --  Only one mutable borrow at a time (enforced by 'in out').

   ---------------------------------------------------------------------------
   --  Borrow Accessors
   ---------------------------------------------------------------------------

   function View_Data (V : Buffer_View) return System.Address
     with Global => null;
   --  Get address of borrowed data (read-only intent)

   function Ref_Data (R : Buffer_Ref) return System.Address
     with Global => null;
   --  Get address of borrowed data (mutable intent)

   function Data (Handle : Buffer_Handle) return System.Address
     with Global => null,
          Pre    => not Is_Null (Handle);
   --  Get address of valid buffer data for direct read/write access.
   --  DEPRECATED: Prefer Borrow/Borrow_Mut for explicit intent.

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

   type Buffer is limited record
      Index : Buffer_Index := Null_Index;
      Data  : aliased Packet_Buffer;
   end record
     with Convention => C;

   type Buffer_Ptr is access all Buffer;

   type Buffer_Handle is limited record
      Ptr : Buffer_Ptr := null;
   end record;

   function Is_Null (H : Buffer_Handle) return Boolean is
     (H.Ptr = null or else H.Ptr.Index = Null_Index);

   ---------------------------------------------------------------------------
   --  Borrow Types Implementation
   --
   --  These wrap access types but enforce borrow semantics at the API level.
   --  Non-limited because they're lightweight views (copying a view is OK).
   ---------------------------------------------------------------------------

   type Buffer_View is record
      Data_Ptr : access constant Packet_Buffer := null;
   end record;

   type Buffer_Ref is record
      Data_Ptr : access Packet_Buffer := null;
   end record;

end Utils.Memory_Pool;
