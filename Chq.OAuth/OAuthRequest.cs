using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Chq.OAuth.Credentials;
using Chq.OAuth.Helpers;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using Windows.Foundation;

namespace Chq.OAuth
{
    public sealed class OAuthRequest
    {
        Dictionary<string, string> QueryParameters = new Dictionary<string, string>();
        Dictionary<string, string> AuthParameters = new Dictionary<string, string>();
        Dictionary<string, string> FormParameters = new Dictionary<string, string>();

        Dictionary<string, string> AllParameters
        {
            get
            {
                Dictionary<string, string> AllParameters = new Dictionary<string, string>();
                foreach (var element in QueryParameters) AllParameters.Add(element.Key, element.Value);
                foreach (var element in AuthParameters) AllParameters.Add(element.Key, element.Value);
                foreach (var element in FormParameters) AllParameters.Add(element.Key, element.Value);
                return AllParameters;
            }
        }

        Uri Url { get; set; }
        string Method { get; set; }
        string Data {get;set;}
        string ContentType {get;set;}

        private OAuthContext _context;
        public OAuthContext Context
        {
            get { return _context; }
        }

        public OAuthRequest(string method, OAuthContext context)
        {
            this.Method = method;
            this._context = context;
        }

        public OAuthRequest ForRequestToken()
        {            
            AuthParameters.Clear();
            QueryParameters.Clear();

            if(Context.CallbackUri != null)
                AuthParameters.Add(OAuthParameters.CALL_BACK, Context.CallbackUri.ToString());
            
            AuthParameters.Add(OAuthParameters.CONSUMER_KEY, Context.ConsumerToken.Token);
            AuthParameters.Add(OAuthParameters.VERSION, "1.0");
            AuthParameters.Add(OAuthParameters.TIMESTAMP, DateTime.UtcNow.SinceEpoch().ToString());
            AuthParameters.Add(OAuthParameters.NONCE, Guid.NewGuid().ToString());
            AuthParameters.Add(OAuthParameters.SIGNATURE_METHOD, Context.SignatureMethodText);

            Url = Context.RequestUri;

            return this;
        }

        public OAuthRequest ForAccessToken(string requestToken, string tokenVerifier)
        {

            QueryParameters.Clear();
            AuthParameters.Clear();

            AuthParameters.Add(OAuthParameters.CONSUMER_KEY, Context.ConsumerToken.Token);
            AuthParameters.Add(OAuthParameters.NONCE, Guid.NewGuid().ToString());
            AuthParameters.Add(OAuthParameters.SIGNATURE_METHOD, Context.SignatureMethodText);
            AuthParameters.Add(OAuthParameters.TIMESTAMP, DateTime.UtcNow.SinceEpoch().ToString());
            AuthParameters.Add(OAuthParameters.TOKEN, requestToken);
            AuthParameters.Add(OAuthParameters.VERIFIER, tokenVerifier);
            AuthParameters.Add(OAuthParameters.VERSION, "1.0");

            Url = Context.AccessUri;

            return this;
        }

        [Obsolete("Please use WithParameters(...)")]
        public OAuthRequest WithQueryParameter(string name, string value)
        {
            if (QueryParameters.ContainsKey(name)) QueryParameters.Remove(name);
            QueryParameters.Add(name, value);
            return this;
        }

        public OAuthRequest WithParameters(object parameters)
        {
            if (parameters != null)
            {
                foreach (var parameter in parameters.GetType().GetTypeInfo().DeclaredProperties)
                {
                    if (parameter.Name.StartsWith("oauth_"))
                    {
                        AuthParameters.Remove(parameter.Name);
                        AuthParameters.Add(parameter.Name, parameter.GetValue(parameters).ToString());
                    }
                    else
                    {
                        if (QueryParameters.ContainsKey(parameter.Name)) QueryParameters.Remove(parameter.Name);
                        QueryParameters.Add(parameter.Name, parameter.GetValue(parameters).ToString());
                    }
                }
            }
            return this;
        }

        public OAuthRequest SetContentTypeTo(string contentType)
        {
            ContentType = contentType;
            return this;
        }

        public OAuthRequest ForResource(string accessToken, Uri protectedResource)
        {
            QueryParameters.Clear();
            AuthParameters.Clear();

            AuthParameters.Add(OAuthParameters.CONSUMER_KEY, Context.ConsumerToken.Token);
            AuthParameters.Add(OAuthParameters.TOKEN, accessToken);
            AuthParameters.Add(OAuthParameters.VERSION, "1.0");
            AuthParameters.Add(OAuthParameters.TIMESTAMP, DateTime.UtcNow.SinceEpoch().ToString());
            AuthParameters.Add(OAuthParameters.NONCE, Guid.NewGuid().ToString());
            AuthParameters.Add(OAuthParameters.SIGNATURE_METHOD, Context.SignatureMethodText);

            Url = protectedResource;

            return this;
        }

        public OAuthRequest WithData(string data)
        {
            Data = data;
            return this;
        }

        public OAuthRequest WithFormEncodedData(object data)
        {
            StringBuilder builder = new StringBuilder();
            if (data != null)
            {
                foreach (var item in data.GetType().GetTypeInfo().DeclaredProperties)
                {
                    if (builder.Length > 0)
                        builder.Append("&");
                    var key = item.Name;
                    builder.Append(key);
                    object value = item.GetValue(data);

                    if (value != null)
                    {                        
                        var stringvalue = value.ToString();
                        FormParameters.Add(key, stringvalue);
                        builder.Append("=");
                        builder.Append(OAuthEncoding.Encode(stringvalue));
                    }
                }
            }
            Data = builder.ToString();

            return SetContentTypeTo(@"application/x-www-form-urlencoded; charset: UTF-8");
            
        }

        public OAuthRequest Sign()
        {
            return Sign(string.Empty);
        }

        public OAuthRequest Sign(string tokenSecret)
        {
            String SigBaseStringParams = "";
            var orderedParameters = AllParameters.OrderBy(d => d.Key);
            foreach (var item in orderedParameters)
            {
                if (SigBaseStringParams != "") SigBaseStringParams += "&";
                SigBaseStringParams += item.Key + "=" + item.Value;
            }

            String SigBaseString = Method.ToUpper() + "&";
            SigBaseString += OAuthEncoding.Encode(Url.ToString()) + "&" + OAuthEncoding.Encode(SigBaseStringParams);

            IBuffer KeyMaterial = CryptographicBuffer.ConvertStringToBinary(Context.ConsumerToken.Secret + "&" + tokenSecret, BinaryStringEncoding.Utf8);
            MacAlgorithmProvider HmacSha1Provider = MacAlgorithmProvider.OpenAlgorithm("HMAC_SHA1");
            CryptographicKey MacKey = HmacSha1Provider.CreateKey(KeyMaterial);
            IBuffer DataToBeSigned = CryptographicBuffer.ConvertStringToBinary(SigBaseString, BinaryStringEncoding.Utf8);
            IBuffer SignatureBuffer = CryptographicEngine.Sign(MacKey, DataToBeSigned);
            String Signature = CryptographicBuffer.EncodeToBase64String(SignatureBuffer);

            AuthParameters.Add(OAuthParameters.SIGNATURE, Signature);

            return this;
        }
#if WINMD
        public IAsyncOperation<string> ExecuteRequest()
        {
            return ExecuteRequestInternal().AsAsyncOperation<string>();
        }
#else
        public Task<String> ExecuteRequest()
        {
            return ExecuteRequestInternal();
        }
#endif

        private async Task<String> ExecuteRequestInternal()
        {
            HttpWebRequest Request;            
            String SigBaseStringParams = "";

            foreach (var item in QueryParameters)
            {
                if (SigBaseStringParams != "") SigBaseStringParams += "&";
                SigBaseStringParams += item.Key + "=" + OAuthEncoding.Encode(item.Value);
            }

            Request = (HttpWebRequest)WebRequest.Create(Url + (String.IsNullOrEmpty(SigBaseStringParams) ? "": "?" + SigBaseStringParams));
            Request.Method = Method.ToUpper();


            if (Method != "GET")
            {
                if (!String.IsNullOrEmpty(ContentType)) Request.ContentType = ContentType;

                if (Data != null)
                {
                    using (var stream = await Request.GetRequestStreamAsync())
                    {
                        var bytes = Encoding.UTF8.GetBytes(Data);
                        stream.Write(bytes, 0, bytes.Length);
                    }
                }
            }

            String authHeader = "OAuth";
            var orderedParameters = AuthParameters.OrderBy(d => d.Key);
            foreach (var item in orderedParameters)
            {
                authHeader += (item.Key != orderedParameters.First().Key ? ", ":" ") + item.Key + "=\"" + OAuthEncoding.Encode(item.Value)+"\"";
            }

            Request.Headers["Authorization"] = authHeader;

            HttpWebResponse Response = (HttpWebResponse)await Request.GetResponseAsync();
            StreamReader ResponseDataStream = new StreamReader(Response.GetResponseStream());

            return ResponseDataStream.ReadToEnd();
        }       
    }
}
