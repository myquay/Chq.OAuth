Chq.OAuth
=========

# Introduction
Chq.OAuth is a simple C# OAuth library for creating OAuth consumers in Windows 8 Metro applications.
This is an early stage project so things will probably change :)

You can grab the latest version on NuGet: https://nuget.org/packages/Chq.OAuth.dll

# Usage
1: Create an OAuthContext object, this holds a whole bunch of informaion about the service that you're communicating with.

```c#
var context =  new OAuthContext(ConsumerKey, ConsumerSecret, RequestUrl, AuthorizeUrl, AccessUrl, CallbackUrl);
```

2: Create a client

```c#
var client =  new Client(context);
```

3: Request a temporary token (The RequestToken) from the OAuth provider

```c#
String requestTokenResponse = await client.MakeRequest("GET")
                    .ForRequestToken()
                    .WithQueryParameter("scope", "email") //Optional, changes depending on provider
                    .Sign()
                    .ExecuteRequest();
                    
client.RequestToken = TokenContainer.Parse(requestTokenResponse);
```

4: Authorize with the temporary RequestToken

```c#
Uri authorizationUri = client.GetAuthorizationUri();
                    
//Authorize the temporary token using the authorizationUri
//One option is to use the supplied WebAuthenticationBroker
WebAuthenticationResult WebAuthenticationResult = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.None, authorizationUri, client.Context.CallbackUri);

//The verification code could be returned in the response
//i.e. Parse it out of WebAuthenticationResult.ResponseData.ToString();
//Or it could be displayed to the user and they will have to enter it into your application manually
String verificationCode = ... 
```

5: Exchange the temporary token for an access token

```c#
String accessTokenResponse = await client.MakeRequest("GET")
                    .ForAccessToken(client.RequestToken.Token, verificationCode)
                    .Sign(client.RequestToken.Secret)
                    .ExecuteRequest();
                    
client.AccessToken = TokenContainer.Parse(accessTokenResponse);
```

6: Yay, you're done! Now you can access protected resources.

```c#
String getResponse = await client.MakeRequest("GET")
                  .ForResource(client.AccessToken.Token, protectedResourceUri)
                  .WithQueryParameter("param", "value") //options
                  .Sign(client.AccessToken.Secret)
                  .ExecuteRequest();
                  
String postResponse = await client.MakeRequest("POST")
                  .WithData(data)
                  .ForResource(client.AccessToken.Token, protectedResourceUri)
                  .Sign(client.AccessToken.Secret)
                  .ExecuteRequest();
```