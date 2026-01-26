--  Utils.Platform - FreeRTOS Implementation
--
--  Implements queue send/receive using ESP-IDF FreeRTOS xQueue API.
--  Queue creation/deletion is handled by C code.

with Interfaces.C; use Interfaces.C;

package body Utils.Platform
  with SPARK_Mode => Off
is

   ---------------------
   --  FreeRTOS Imports
   ---------------------

   --  xQueueSend(xQueue, pvItemToQueue, xTicksToWait)
   --  Returns pdTRUE (1) on success, pdFALSE (0) on failure
   function xQueueSend
     (Queue       : System.Address;
      Item        : System.Address;
      Ticks_Wait  : unsigned) return int
   with Import, Convention => C, External_Name => "xQueueSend";

   --  xQueueReceive(xQueue, pvBuffer, xTicksToWait)
   function xQueueReceive
     (Queue       : System.Address;
      Buffer      : System.Address;
      Ticks_Wait  : unsigned) return int
   with Import, Convention => C, External_Name => "xQueueReceive";

   --  portMAX_DELAY for infinite wait
   portMAX_DELAY : constant unsigned := unsigned'Last;

   --  pdMS_TO_TICKS macro equivalent (ESP-IDF default: 1000 Hz = 1ms tick)
   function Ms_To_Ticks (Ms : Natural) return unsigned is
   begin
      if Ms = Natural'Last then
         return portMAX_DELAY;
      else
         return unsigned (Ms);  --  1:1 at 1000 Hz tick rate
      end if;
   end Ms_To_Ticks;

   ---------------------
   --  Queue Operations
   ---------------------

   function Queue_Is_Valid (Queue : Queue_Handle) return Boolean is
   begin
      return Queue /= Null_Queue;
   end Queue_Is_Valid;

   function Queue_Send
     (Queue      : Queue_Handle;
      Descriptor : Buffer_Descriptor;
      Timeout_Ms : Natural := 0) return Boolean
   is
      Item   : aliased Buffer_Descriptor := Descriptor;
      Result : int;
   begin
      Result := xQueueSend
        (System.Address (Queue),
         Item'Address,
         Ms_To_Ticks (Timeout_Ms));
      return Result /= 0;  --  pdTRUE = 1, pdFALSE = 0
   end Queue_Send;

   function Queue_Receive
     (Queue      : Queue_Handle;
      Descriptor : out Buffer_Descriptor;
      Timeout_Ms : Natural := Natural'Last) return Boolean
   is
      Result : int;
   begin
      Result := xQueueReceive
        (System.Address (Queue),
         Descriptor'Address,
         Ms_To_Ticks (Timeout_Ms));
      return Result /= 0;
   end Queue_Receive;

end Utils.Platform;
