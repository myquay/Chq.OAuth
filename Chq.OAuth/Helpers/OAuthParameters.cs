using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Chq.OAuth.Helpers
{
    static class OAuthParameters
    {
        public static string CALL_BACK = "oauth_callback";
        public static string CONSUMER_KEY = "oauth_consumer_key";
        public static string VERSION = "oauth_version";
        public static string TIMESTAMP = "oauth_timestamp";
        public static string NONCE = "oauth_nonce";
        public static string SIGNATURE_METHOD = "oauth_signature_method";
        public static string TOKEN = "oauth_token";
        public static string VERIFIER = "oauth_verifier";
        public static string SIGNATURE = "oauth_signature";
    }
}
