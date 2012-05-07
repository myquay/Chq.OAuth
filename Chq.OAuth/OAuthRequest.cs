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

namespace Chq.OAuth
{
    public class OAuthRequest
    {
        Dictionary<string, string> QueryParameters = new Dictionary<string, string>();
        Dictionary<string, string> AuthParameters = new Dictionary<string, string>();

        Dictionary<string, string> AllParameters
        {
            get
            {
                Dictionary<string, string> AllParameters = new Dictionary<string, string>();
                foreach (var element in QueryParameters) AllParameters.Add(element.Key, element.Value);
                foreach (var element in AuthParameters) AllParameters.Add(element.Key, element.Value);
                return AllParameters;
            }
        }

        Uri Url { get; set; }
        string Method { get; set; }
        string Data {get;set;}
        string ContentType {get;set;}

        protected OAuthContext _context;
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

        public OAuthRequest Sign(string tokenSecret = "")
        {
            String SigBaseStringParams = "";
            var orderedParameters = AllParameters.OrderBy(d => d.Key);
            foreach (var item in orderedParameters)
            {
                if (SigBaseStringParams != "") SigBaseStringParams += "&";
                SigBaseStringParams += item.Key + "=" + OAuthEncoding.Encode(item.Value);
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

        public async Task<String> ExecuteRequest()
        {
            HttpWebRequest Request;


            if (Method == "GET")
            {
                String SigBaseStringParams = "";
                foreach (var item in QueryParameters)
                {
                    if (SigBaseStringParams != "") SigBaseStringParams += "&";
                    SigBaseStringParams += item.Key + "=" + OAuthEncoding.Encode(item.Value);
                }

                Request = (HttpWebRequest)WebRequest.Create(Url + (String.IsNullOrEmpty(SigBaseStringParams) ? "": "?" + SigBaseStringParams));
                Request.Method = Method.ToUpper();
            }
            else
            {


                Request = (HttpWebRequest)WebRequest.Create(Url);
                Request.Method = Method.ToUpper();
                if (!String.IsNullOrEmpty(ContentType)) Request.ContentType = ContentType;

                if (Data != null)
                {
                    var stream = await Request.GetRequestStreamAsync();
                    StreamWriter stOut = new StreamWriter(stream, System.Text.Encoding.UTF8);
                    stOut.Write(Data);
                    await stOut.FlushAsync();
                    stOut.Dispose();
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
