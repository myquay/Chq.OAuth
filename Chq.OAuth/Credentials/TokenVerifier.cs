using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chq.OAuth.Credentials
{
    public sealed class TokenVerifier
    {
        public string Verifier { get; set; }

        public static TokenVerifier Parse(string tokenString)
        {
            String oauth_verifier = null;

            String[] keyValPairs = tokenString.Split('&');

            for (int i = 0; i < keyValPairs.Length; i++)
            {
                String[] splits = keyValPairs[i].Split('=');
                switch (splits[0])
                {
                    case "oauth_verifier":
                        oauth_verifier = splits[1];
                        break;
                }
            }

            return new TokenVerifier { Verifier = oauth_verifier };
        }
    }
}
