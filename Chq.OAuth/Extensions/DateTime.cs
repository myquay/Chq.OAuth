using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System
{
    public static class DateTimeExtensions
    {
        public static long SinceEpoch(this DateTime time)
        {
            return (long)(time - new DateTime(1970, 1, 1, 0, 0, 0, 0)).TotalSeconds;
        } 
    }
}
