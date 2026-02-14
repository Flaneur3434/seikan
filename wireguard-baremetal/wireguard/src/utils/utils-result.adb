package body Utils.Result
  with Spark_Mode => On
is
   function Ok (V : T) return Result is
   begin
      return (K => Is_Ok, Ok => V);
   end Ok;

   function Err (V : E) return Result is
   begin
      return (K => Is_Err, Err => V);
   end Err;
end Utils.Result;
