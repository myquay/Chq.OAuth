using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chq.OAuth.Credentials
{
    public sealed class TokenContainer
    {
        
        public string Token { get; set; }
        public string Secret { get; set; }

        public static TokenContainer Parse(string tokenString)
        {
            String oauth_token = null;
            String oauth_token_secret = null;

            String[] keyValPairs = tokenString.Split('&');

            for (int i = 0; i < keyValPairs.Length; i++)
            {
                String[] splits = keyValPairs[i].Split('=');
                switch (splits[0])
                {
                    case "oauth_token":
                        oauth_token = splits[1];
                        break;
                    case "oauth_token_secret":
                        oauth_token_secret = splits[1];
                        break;
                }
            }

            return new TokenContainer { Token = oauth_token, Secret = oauth_token_secret};
        }
    }
}
