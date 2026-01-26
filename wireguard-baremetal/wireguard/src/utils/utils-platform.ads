--  Utils.Platform - Platform Abstraction Interface
--
--  Defines abstract operations for platform-specific primitives:
--    - Thread-safe queues for Buffer_Descriptor (created by C code)
--
--  DESIGN PHILOSOPHY:
--    - Core WireGuard code is platform-agnostic
--    - Queue handles are created/destroyed by C code
--    - Ada code only sends/receives Buffer_Descriptors
--    - Only Buffer_Descriptor crosses thread boundaries (cheap 16-byte copy)
--
--  This is a PRIVATE package - only visible within Utils hierarchy.

with System;
with Utils.Ring_Buffer;

private package Utils.Platform
  with SPARK_Mode => Off
is

   use Utils.Ring_Buffer;

   --  Opaque queue handle (created by C code, passed to Ada)
   type Queue_Handle is new System.Address;

   Null_Queue : constant Queue_Handle :=
      Queue_Handle (System.Null_Address);

   ---------------------
   --  Queue Operations
   ---------------------

   --  Check if queue handle is valid
   function Queue_Is_Valid (Queue : Queue_Handle) return Boolean
     with Inline;

   --  Send a descriptor to the queue
   --  Timeout_Ms = 0 means no wait (immediate return if full)
   --  Returns True on success, False if queue full or timeout
   function Queue_Send
     (Queue      : Queue_Handle;
      Descriptor : Buffer_Descriptor;
      Timeout_Ms : Natural := 0) return Boolean
     with Pre => Queue_Is_Valid (Queue);

   --  Receive a descriptor from the queue (blocking with timeout)
   --  Timeout_Ms = 0 means no wait, Natural'Last means wait forever
   --  Returns True on success with Descriptor filled in
   function Queue_Receive
     (Queue      : Queue_Handle;
      Descriptor : out Buffer_Descriptor;
      Timeout_Ms : Natural := Natural'Last) return Boolean
     with Pre => Queue_Is_Valid (Queue);

end Utils.Platform;
