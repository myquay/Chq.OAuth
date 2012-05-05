using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chq.OAuth.Credentials;

namespace Chq.OAuth
{
    public class Client
    {
        public enum OAuthState { RequestRequired, TokenRequired, Ready }

        protected OAuthContext _context;
        public OAuthContext Context
        {
            get { return _context; }
        }

        public TokenContainer RequestToken { get; set; }
        public TokenContainer AccessToken { get; set; }

        public Client(OAuthContext context)
        {
            _context = context;
        }

        public OAuthRequest MakeRequest(string method)
        {
            return new OAuthRequest(method, Context);
        }

        public void Reset()
        {
            RequestToken = null;
            AccessToken = null;
        }

        public OAuthState State()
        {
            if (RequestToken == null) return OAuthState.RequestRequired;
            else if (AccessToken == null) return OAuthState.TokenRequired;
            else return OAuthState.Ready;
        }
    }
}
