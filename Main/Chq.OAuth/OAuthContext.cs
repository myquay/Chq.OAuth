using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chq.OAuth.Credentials;

namespace Chq.OAuth
{
    public class OAuthContext
    {
        public enum SignatureMethods { HMAC_SHA1 }

        public Uri RequestUri { get; set; }
        public Uri AuthorizationUri { get; set; }
        public Uri AccessUri { get; set; }
        public Uri CallbackUri { get; set; }

        public TokenContainer ConsumerToken { get; set; } 

        private bool _isOutOfBand = false;
        public bool IsOutOfBand { 
            get { return _isOutOfBand; } 
            set { _isOutOfBand = value; } 
        }

        private SignatureMethods _signatureMethod = SignatureMethods.HMAC_SHA1;
        public SignatureMethods SignatureMethod { 
            get { return _signatureMethod; }
            set { _signatureMethod = value; }
        }

        public string SignatureMethodText
        {
            get
            {
                switch (SignatureMethod)
                {
                    case SignatureMethods.HMAC_SHA1:
                        return "HMAC-SHA1";
                        break;
                    default:
                        return "";
                }
            }
        }

        public OAuthContext() { }

        public OAuthContext(
            string consumerKey,
            string consumerSecret,
            string requestUri,
            string authorizationUri,
            string accessUri,
            string callbackUri = null,
            bool isOutOfBand = false,
            SignatureMethods signatureMethod = SignatureMethods.HMAC_SHA1)
        {
            ConsumerToken = new TokenContainer
            {
                Token = consumerKey,
                Secret = consumerSecret,
                Type = TokenContainer.Types.Client
            };

            RequestUri = new Uri(requestUri);
            AuthorizationUri = new Uri(authorizationUri);
            AccessUri = new Uri(accessUri);
            if (callbackUri != null) CallbackUri = new Uri(callbackUri);
            
            IsOutOfBand = isOutOfBand;
            SignatureMethod = signatureMethod;
        }
    }
}
