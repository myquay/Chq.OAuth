using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Chq.OAuth.Credentials;
using System.Reflection;

namespace Chq.OAuth
{
    public sealed class Client
    {
        private OAuthContext _context;
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

        public Uri GetAuthorizationUri()
        {
            return GetAuthorizationUri(null);
        }

        public Uri GetAuthorizationUri(object parameters)
        {
            string queryString = String.Empty;

            if (parameters != null)
            {
                Dictionary<string, string> queryParameters = new Dictionary<string, string>();
#if WINMD
                foreach (var parameter in parameters.GetType().GetTypeInfo().DeclaredProperties)
                {
                    if (queryParameters.ContainsKey(parameter.Name)) queryParameters.Remove(parameter.Name);
                    queryParameters.Add(parameter.Name, parameter.GetValue(parameters).ToString());
                }
#else
                foreach (var parameter in parameters.GetType().GetProperties())
                {
                    if (queryParameters.ContainsKey(parameter.Name)) queryParameters.Remove(parameter.Name);
                    queryParameters.Add(parameter.Name, parameter.GetValue(parameters, null).ToString());
                }
#endif
                foreach (var parameter in queryParameters)
                {
                    queryString = String.Format("{0}&{1}={2}", queryString, parameter.Key, Uri.EscapeDataString(parameter.Value));
                }
            }

            return new Uri(Context.AuthorizationUri.ToString() + "?oauth_token=" + RequestToken.Token + queryString);
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
