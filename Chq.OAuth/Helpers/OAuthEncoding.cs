using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chq.OAuth.Helpers
{
    public sealed class OAuthEncoding
    {

        //http://tools.ietf.org/html/rfc5849#section-3.6
        public static string Encode(string toEncode)
        {
            String encoded = "";

            for (int Index = 0; Index < toEncode.Length; Index++)
            {
                char charToEncode = toEncode[Index];
                if ((charToEncode >= 'A' && charToEncode <= 'Z') || //ALPHA
                    (charToEncode >= 'a' && charToEncode <= 'z') ||
                    (charToEncode >= '0' && charToEncode <= '9') || //DIGIT
                    charToEncode == '-' ||                          //RESERVED
                    charToEncode == '.' ||
                    charToEncode == '_' ||
                    charToEncode == '~') 
                {
                    encoded += charToEncode;
                }
                else
                {
                    encoded += "%" + String.Format("{0:X}", (int)charToEncode);
                }
            }
            return encoded;
        }
    }
}
