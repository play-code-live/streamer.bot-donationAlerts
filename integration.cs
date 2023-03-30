using System;
using System.Net;
using System.Text;
using System.Web;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Threading;
using System.Timers;

///----------------------------------------------------------------------------
///   Module:     DonationAlertsIntegration
///   Author:     play_code (https://twitch.tv/play_code)
///   Email:      info@play-code.live
///   Repository: https://github.com/play-code-live/streamer.bot-donationAlerts
///----------------------------------------------------------------------------
public class CPHInline
{
    public class PrefixedLogger
    {
        private IInlineInvokeProxy _CPH { get; set; }
        private const string Prefix = "-- Donation Alerts:";

        public PrefixedLogger(IInlineInvokeProxy _CPH)
        {
            this._CPH = _CPH;
        }
        public void WebError(WebException e)
        {
            var response = (HttpWebResponse)e.Response;
            var statusCodeResponse = response.StatusCode;
            int statusCodeResponseAsInt = ((int)response.StatusCode);
            Error("WebException with status code " + statusCodeResponseAsInt.ToString(), statusCodeResponse);
        }
        public void Error(string message)
        {
            message = string.Format("{0} {1}", Prefix, message);
            _CPH.LogWarn(message);
        }
        public void Error(string message, params Object[] additional)
        {
            string finalMessage = message;
            foreach (var line in additional)
            {
                finalMessage += ", " + line;
            }
            this.Error(finalMessage);
        }
        public void Debug(string message)
        {
            message = string.Format("{0} {1}", Prefix, message);
            _CPH.LogDebug(message);
        }
        public void Debug(string message, params Object[] additional)
        {
            string finalMessage = message;
            foreach (var line in additional)
            {
                finalMessage += ", " + line;
            }
            this.Debug(finalMessage);
        }
    }
    private Service Service { get; set; }
    private SocketService SocketService { get; set; }
    private PrefixedLogger Logger { get; set; }

    private const string DefaultHandlerActionName = "DonationHandler_Default";
    private const string TextPleaseConnect = "Please connect to DonationAlerts using the Webpage that opened to obtain your token. " +
            "Для продолжения подтвердите авторизацию в появившемся окне браузера";

    public void Init()
    {
        CPH.ExecuteMethod("DonationAlert Update Checker", "CheckAndAnnounce");
        Logger = new PrefixedLogger(CPH);
        Service = new Service(new Client(), Logger);

        SocketService = new SocketService(Service, Logger);
    }
    public void Dispose()
    {
        SocketService.Close();
    }
    public bool CreateAuthLink()
    {
        string authLink = Service.GetAuthLink();
        CPH.SendMessage(TextPleaseConnect);
        System.Diagnostics.Process.Start(authLink);
        Logger.Debug("Opened URL in the default browser. Awaiting for confirmation");

        return Service.ServeAndListenAuth(delegate (string code)
        {
            CPH.SetGlobalVar("daCode", code, true);
            Logger.Debug("code : " + code);
            return code;
        });
    }
    public bool ObtainAccessToken()
    {
        string code = CPH.GetGlobalVar<string>("daCode");
        if (code == "")
        {
            Logger.Debug("Code argument has not arrivied. Make sure you initialized connection for the DA");
            return false;
        }

        var tokenData = Service.ObtainToken(code);
        if (tokenData == null)
            return false;

        CPH.SetGlobalVar("daAccessToken", tokenData.AccessToken, true);
        CPH.SetGlobalVar("daRefreshToken", tokenData.RefreshToken, true);

        Logger.Debug("AccessToken and RefreshToken are obtained successfully");

        return true;
    }
    public bool RefreshAccessToken()
    {
        if (args.ContainsKey("refresh_token_recursion_protection"))
            return false;
        Logger.Debug("Refreshing access token");

        string refreshToken = CPH.GetGlobalVar<string>("daRefreshToken");
        if (refreshToken == "")
        {
            Logger.Debug("RefreshToken argument has not arrived. Make sure you initialized connection for the DA");
            return false;
        }

        var tokenData = Service.RefreshToken(refreshToken);
        if (tokenData == null)
            return false;

        CPH.SetGlobalVar("daAccessToken", tokenData.AccessToken, true);
        CPH.SetGlobalVar("daRefreshToken", tokenData.RefreshToken, true);
        CPH.SetArgument("refresh_token_recursion_protection", true);

        return true;
    }
    public bool GetProfileInfo()
    {
        Logger.Debug("Obtaining socket token");
        string accessToken = CPH.GetGlobalVar<string>("daAccessToken");
        if (accessToken == "")
            return false;

        var profileInfo = Service.GetProfileInfo(accessToken);
        if (profileInfo == null)
            return this.RefreshAccessToken() && this.GetProfileInfo();

        CPH.SetGlobalVar("daSocketToken", profileInfo.SocketConnectionToken, true);
        CPH.SetGlobalVar("daUserId", profileInfo.Id, true);

        return true;
    }
    public bool DonationCheckerLoop()
    {
        string accessToken = CPH.GetGlobalVar<string>("daAccessToken");
        if (string.IsNullOrEmpty(accessToken))
        {
            CPH.SendMessage("Необходимо выполнить авторизацию в DonationAlerts. Введите команду !da_connect");
            throw new Exception("Unauthorized");
        }

        SocketService
            .On(SocketService.EventStarted, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Ready to connect to the socket");
            })
            .On(SocketService.EventConnected, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Connected to the socket");
                CPH.SendMessage("DonationAlert Background Watcher is ON");
            })
            .On(SocketService.EventReconnected, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Reconnected to the socket");
            })
            .On(SocketService.EventDisconnected, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Disconnected from the socket", Data["description"]);
            })
            .On(SocketService.EventRecievedDonation, delegate (string Event, Dictionary<string, string> Data)
            {
                ExportDonation(Data);
                string targetActionName = string.Format("DonationHandler_{0}", Data["amount"]);
                if (CPH.ActionExists(targetActionName))
                {
                    CPH.RunAction(targetActionName, false);
                }
                else if (CPH.ActionExists(DefaultHandlerActionName))
                {
                    CPH.RunAction(DefaultHandlerActionName);
                }
            });


        SocketService.Start(accessToken);
        return true;
    }
    private void ExportDonation(Dictionary<string, string> Donation)
    {
        string username = "Anonymous";
        if (!string.IsNullOrEmpty(Donation["username"]))
            username = Donation["username"];

        CPH.SetArgument("daName", Donation["name"]);
        CPH.SetArgument("daUsername", username);
        CPH.SetArgument("daMessage", Donation["message"]);
        CPH.SetArgument("daAmount", Donation["amount"]);
        CPH.SetArgument("daCurrency", Donation["currency"]);
        CPH.SetArgument("daAmountConverted", Donation["amount_in_user_currency"]);
    }
}

public class SocketService
{
    private const string SocketHost = "wss://centrifugo.donationalerts.com/connection/websocket";

    public const string EventStarted = "started";
    public const string EventConnected = "connected";
    public const string EventDisconnected = "disconnected";
    public const string EventReconnected = "reconnected";
    public const string EventAuthorized = "authorized";
    public const string EventSubscribed = "subscribed";

    public const string EventRecievedMessage = "recieved_message";
    public const string EventRecievedDonation = "recieved_donation";
    private EventObserver Observer { get; set; }
    private Service DaService { get; set; }
    private ClientWebSocket Socket { get; set; }
    private CPHInline.PrefixedLogger Logger { get; set; }

    private const int BufferSize = 3072;

    public SocketService(Service service, CPHInline.PrefixedLogger Logger)
    {
        Observer = new EventObserver();
        DaService = service;
        this.Logger = Logger;
    }
    public SocketService On(string EventName, EventObserver.Handler handler)
    {
        Observer.Subscribe(EventName, handler);
        return this;
    }
    public Task Start(string AccessToken)
    {
        return ConnectAndProccess(AccessToken);
    }
    public void Close()
    {
        try
        {
            if (Socket == null)
                return;
            Socket.Abort();
            Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
            Socket = null;
            Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", "manual" } });
        }
        catch (Exception) { }

    }
    private Task ConnectAndProccess(string AccessToken, bool isReconnected = false)
    {
        var userProfile = DaService.GetProfileInfo(AccessToken);

        Socket = new ClientWebSocket();
        Observer.Dispatch(EventStarted, null);
        Socket.ConnectAsync(new Uri(SocketHost), CancellationToken.None).GetAwaiter().GetResult();
        Observer.Dispatch(isReconnected ? EventReconnected : EventConnected);

        var buf = new ArraySegment<byte>(new byte[BufferSize]);

        if (Socket.State == WebSocketState.Open)
        {
            string socketClientId = ObtainSocketClientId(userProfile.SocketConnectionToken);
            var channelInfo = DaService.ObtainChannelSubscribeToken(AccessToken, userProfile.Id, socketClientId);
            this.SubscribeToTheChannel(channelInfo.Channel, channelInfo.Token);
        }

        try
        {
            while (Socket.State == WebSocketState.Open)
            {
                Logger.Debug("Waiting for a message");
                var result = Socket.ReceiveAsync(buf, CancellationToken.None).GetAwaiter().GetResult();
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                    Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
                }
                else
                {
                    isReconnected = false;
                    Logger.Debug("Recieved message");
                    string rawMessage = Encoding.ASCII.GetString(buf.Array, 0, result.Count);
                    Observer.Dispatch(EventRecievedMessage, new Dictionary<string, string> { { "message", rawMessage } });
                    Logger.Debug(rawMessage);
                    try
                    {
                        var donationEvent = JsonConvert.DeserializeObject<Dictionary<string, DonationResponse>>(rawMessage);
                        var donation = donationEvent["result"].Data.Donation;
                        if (donation.Amount <= 0)
                            continue;

                        Observer.Dispatch(EventRecievedDonation, donation.ToDictionary());
                    }
                    catch (Exception) { }
                }
            }
        }
        catch (Exception)
        {
            if (isReconnected)
            {
                Logger.Debug("Cannot reconnect to socket too many times");
                return null;
            }
        }

        return ConnectAndProccess(AccessToken, true);
    }

    private string ObtainSocketClientId(string SocketToken)
    {
        if (Socket == null || Socket.State != WebSocketState.Open)
            throw new Exception("Socket is closed");


        var request = new SocketClientRequest
        {
            Parameters = new SocketClientRequestParams
            {
                Token = SocketToken,
            }
        };
        var payload = JsonConvert.SerializeObject(request);

        Socket.SendAsync(
            new ArraySegment<byte>(Encoding.ASCII.GetBytes(payload)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();

        var buffer = new ArraySegment<byte>(new byte[BufferSize]);
        var result = Socket.ReceiveAsync(buffer, CancellationToken.None).GetAwaiter().GetResult();
        Logger.Debug("Auth response resieved");
        if (result.MessageType == WebSocketMessageType.Close)
        {
            Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
            Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
            throw new Exception("Socket has closed connection");
        }
        Logger.Debug("Recieved auth message");

        var authResponse = JsonConvert.DeserializeObject<SocketClientResponse>(Encoding.ASCII.GetString(buffer.Array, 0, result.Count));

        Observer.Dispatch(EventAuthorized, new Dictionary<string, string> { { "client", authResponse.Data.Client }, { "version", authResponse.Data.Version } });

        return authResponse.Data.Client;
    }
    private void SubscribeToTheChannel(string Channel, string ChannelToken)
    {
        var request = new SubscribeRequest
        {
            Data = new SubscribeRequestData { Channel = Channel, Token = ChannelToken },
        };
        var payload = JsonConvert.SerializeObject(request);
        Socket.SendAsync(
            new ArraySegment<byte>(Encoding.ASCII.GetBytes(payload)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();
        Logger.Debug("Subscribe request has been sent");

        var buf = new ArraySegment<byte>(new byte[BufferSize]);

        for (int i = 0; i < 2; i++)
        {
            var result = Socket.ReceiveAsync(buf, CancellationToken.None).GetAwaiter().GetResult();
            Logger.Debug("Subscribe response resieved");
            if (result.MessageType == WebSocketMessageType.Close)
            {
                Socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
                throw new Exception("Socket has closed connection");
            }
            var jsonResponse = Encoding.ASCII.GetString(buf.Array, 0, result.Count);
            Logger.Debug("Subscribe response", jsonResponse);
            var response = JsonConvert.DeserializeObject<SubscribeResponse>(jsonResponse);
            if (response.Id != 0)
                continue;
            if (response.Data.Channel != Channel)
                throw new Exception("Cannot subscribe to the channel");
            break;
        }

        Logger.Debug("Subscribed to the channel", Channel);
        Observer.Dispatch(EventSubscribed, new Dictionary<string, string> { { "channel", Channel } });
    }

    private class SocketClientRequest
    {
        [JsonProperty("id")]
        public int Id = 1;
        [JsonProperty("params")]
        public SocketClientRequestParams Parameters { get; set; }
    }
    private class SocketClientRequestParams
    {
        [JsonProperty("token")]
        public string Token { get; set; }
    }
    private class SocketClientResponse
    {
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("result")]
        public SocketClientResponseData Data { get; set; }
    }
    private class SocketClientResponseData
    {
        [JsonProperty("client")]
        public string Client;
        [JsonProperty("version")]
        public string Version;
    }
    private class SubscribeRequest
    {
        [JsonProperty("id")]
        public int Id = 2;
        [JsonProperty("method")]
        public int Method = 1;
        [JsonProperty("params")]
        public SubscribeRequestData Data { get; set; }
    }
    private class SubscribeRequestData
    {
        [JsonProperty("channel")]
        public string Channel { get; set; }
        [JsonProperty("token")]
        public string Token { get; set; }
    }
    private class SubscribeResponse
    {
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("result")]
        public SubscribeResponseData Data { get; set; }
    }
    private class SubscribeResponseData
    {
        [JsonProperty("recoverable")]
        public bool IsRecoverable = false;
        [JsonProperty("seq")]
        public int seq = 0;
        [JsonProperty("type")]
        public int Type { get; set; }
        [JsonProperty("channel")]
        public string Channel { get; set; }
    }
    private class DonationResponse
    {
        [JsonProperty("channel")]
        public string Channel { get; set; }
        [JsonProperty("data")]
        public DonationResponseData Data = new DonationResponseData();
    }
    private class DonationResponseData
    {
        [JsonProperty("seq")]
        public int Seq { get; set; }
        [JsonProperty("data")]
        public DonationData Donation = new DonationData();
    }
    private class DonationData
    {
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("username")]
        public string UserName { get; set; }
        [JsonProperty("message")]
        public string Message { get; set; }
        [JsonProperty("amount")]
        public double Amount { get; set; }
        [JsonProperty("currency")]
        public string Currency { get; set; }
        [JsonProperty("amount_in_user_currency")]
        public double AmountInUserCurrency { get; set; }

        public Dictionary<string, string> ToDictionary()
        {
            return new Dictionary<string, string>
            {
                { "id", Id.ToString() },
                { "name", Name },
                { "username", UserName },
                { "message", Message },
                { "amount", Amount.ToString() },
                { "currency", Currency },
                { "amount_in_user_currency", AmountInUserCurrency.ToString() },
            };
        }
    }
}
public class Service
{
    public delegate string HandleCode(string code);

    private const string RedirectUrl = "http://127.0.0.1:8554/donationAlertsRedirectUri/";
    private const string DefaultScope = "oauth-donation-index oauth-user-show oauth-donation-subscribe";

    private const string EndpointAuthorize = "/oauth/authorize";
    private const string EndpointToken = "/oauth/token";
    private const string EndpointProfileInfo = "/api/v1/user/oauth";
    private const string EndpointSubscribe = "/api/v1/centrifuge/subscribe";

    // Вы можете изменить эти значения, если необходимо
    // см. https://www.donationalerts.com/application/clients
    private const string ClientId = "10462";
    private const string ClientSecret = "nFdbaXencaGEbFizpwUyDWMuVPI49Y53Y7SGdAmw";
    private CPHInline.PrefixedLogger Logger { get; set; }
    private Client Client { get; set; }
    private HttpListener Listener = null;

    public Service(Client Client, CPHInline.PrefixedLogger Logger)
    {
        this.Client = Client;
        this.Logger = Logger;
    }
    public bool ServeAndListenAuth(HandleCode Handler)
    {
        try
        {
            Listener = new HttpListener();
            Listener.Prefixes.Add(RedirectUrl);
            Listener.Start();
            Func<Task> func = new Func<Task>(async () => {
                bool runServer = true;
                while (runServer)
                {
                    Logger.Debug("Server is waiting ...");
                    HttpListenerContext context = await Listener.GetContextAsync();
                    HttpListenerRequest request = context.Request;
                    HttpListenerResponse resp = context.Response;
                    var queryDictionary = HttpUtility.ParseQueryString(request.Url.Query);
                    string code = queryDictionary["code"];
                    Handler(code);

                    string pageData = "<!DOCTYPE html><html><head><title>Интеграция DonationAlerts + Streamer.bot</title><meta charset=\"UTF-8\"><link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha2/dist/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-aFq/bzH65dt+w6FI2ooMVUpc+21e0SRygnTpmBvdBgSdnuTN7QbdgL+OapgHtvPp\" crossorigin=\"anonymous\"><style>body{background-color:#111}</style></head><body><div class=\"container text-center mt-5 text-white-50\"><h3>Успешно авторизован</h3><p>Вы можете закрыть эту вкладку</p><iframe src=\"https://player.twitch.tv/?channel=play_code&parent=127.0.0.1\" frameborder=\"0\" allowfullscreen=\"true\" scrolling=\"no\" height=\"378\" width=\"620\"></iframe><hr><p class=\"font-monospace\">Спасибо за использование интеграции!<br>Если вы столкнулись с любыми сложностями или хотите предложить улучшение функционала,<br>воспользуйтесь секцией <strong>Issues</strong> на <a href=\"https://github.com/play-code-live/streamer.bot-donationAlerts/issues/new\">GitHub</a><br>❤️</p></div></body></html>";
                    byte[] data = Encoding.UTF8.GetBytes(pageData);
                    resp.ContentType = "text/html";
                    resp.ContentEncoding = Encoding.UTF8;
                    resp.ContentLength64 = data.LongLength;
                    await context.Response.OutputStream.WriteAsync(data, 0, data.Length);
                    resp.Close();
                    runServer = false;
                    Listener.Close();
                }
            });
            Task listenTask = func.Invoke();
            var forceCloseTimer = new System.Timers.Timer(30000);
            forceCloseTimer.Elapsed += ForceCloseServer;
            forceCloseTimer.AutoReset = true;
            forceCloseTimer.Enabled = true;

            listenTask.GetAwaiter().GetResult();
            Listener.Close();
        }
        catch (WebException e)
        {
            Logger.Debug(e.Status.ToString());
            return false;
        }

        return true;
    }
    public string GetAuthLink()
    {
        string url = Client.TargetHost + EndpointAuthorize;
        return string.Format("{0}?client_id={1}&redirect_uri={2}&scope={3}&response_type=code", url, ClientId, GetEncodedRedirectUri(), DefaultScope);
    }
    public ProfileInfoData GetProfileInfo(string accessToken)
    {
        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + accessToken }
        };

        try
        {
            string json = Client.GET(EndpointProfileInfo, new Dictionary<string, string>(), headers);
            ProfileInfoResponse profile = JsonConvert.DeserializeObject<ProfileInfoResponse>(json);
            Logger.Debug("Retrieved user profile info", profile.Data.Id, json);

            return profile.Data;
        }
        catch (WebException e)
        {
            Logger.WebError(e);
            throw e;
        }
    }
    public TokenResponse ObtainToken(string Code)
    {
        var values = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "code", Code },
            { "redirect_uri", RedirectUrl }
        };

        try
        {
            string json = Client.POST(EndpointToken, values);
            Logger.Debug("Request to the token API has been performed");
            TokenResponse tokenData = JsonConvert.DeserializeObject<TokenResponse>(json);

            return tokenData;
        }
        catch (WebException e)
        {
            Logger.WebError(e);
            return null;
        }
    }
    public TokenResponse RefreshToken(string refreshToken)
    {
        var values = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "refresh_token", refreshToken },
            { "scope", DefaultScope }
        };

        try
        {
            string json = Client.POST(EndpointToken, values);
            Logger.Debug("Request to the token API has been performed");
            return JsonConvert.DeserializeObject<TokenResponse>(json);
        }
        catch (WebException e)
        {
            Logger.WebError(e);
            return null;
        }
    }
    public ChannelSubscribeResponse ObtainChannelSubscribeToken(string AccessToken, int UserId, string SocketClientId)
    {
        var request = new ChannelSubscribeRequest
        {
            Client = SocketClientId,
            Channels = new List<string>() { { string.Format("[$alerts:donation_{0}]", UserId) } }
        };
        string payload = JsonConvert.SerializeObject(request);

        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + AccessToken }
        };

        try
        {
            var response = Client.POST(EndpointSubscribe, payload, headers);
            var channels = JsonConvert.DeserializeObject<Dictionary<string, List<ChannelSubscribeResponse>>>(response);
            if (channels["channels"].Count == 0)
                throw new Exception("Cannot fetch channels and it's tokens");

            return channels["channels"][0];
        }
        catch (WebException e)
        {
            Logger.WebError(e);
            throw e;
        }
    }

    private string GetEncodedRedirectUri()
    {
        return HttpUtility.UrlEncode(RedirectUrl);
    }
    private void ForceCloseServer(Object source, ElapsedEventArgs e)
    {
        Logger.Debug("Timer invoked");
        if (Listener != null && Listener.IsListening)
        {
            Listener.Close();
            Logger.Debug("Server has been closed by timeout");
        }
    }

    public class TokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
    }
    public class ProfileInfoResponse
    {
        [JsonProperty("data")]
        public ProfileInfoData Data;
    }
    public class ProfileInfoData
    {
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("code")]
        public string Code { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("avatar")]
        public string Avatar { get; set; }
        [JsonProperty("email")]
        public string Email { get; set; }
        [JsonProperty("socket_connection_token")]
        public string SocketConnectionToken;
    }
    public class ChannelSubscribeResponse
    {
        [JsonProperty("channel")]
        public string Channel;
        [JsonProperty("token")]
        public string Token;
    }
    public class ChannelSubscribeRequest
    {
        [JsonProperty("client")]
        public string Client { get; set; }
        [JsonProperty("channels")]
        public List<string> Channels { get; set; }
    }
}
public class Client
{
    public const string TargetHost = "https://www.donationalerts.com";

    public string GET(string endpoint, Dictionary<string, string> parameters, Dictionary<string, string> headers)
    {
        var queryParams = new List<string>();
        foreach (var parameter in parameters)
        {
            queryParams.Add(string.Format("{0}={1}", parameter.Key, parameter.Value));
        }
        endpoint += "?" + String.Join("&", queryParams);
        return this.Perform(WebRequestMethods.Http.Get, TargetHost + endpoint, new Dictionary<string, string>(), headers);
    }
    public string GET(string endpoint, Dictionary<string, string> parameters)
    {
        return this.GET(endpoint, parameters, new Dictionary<string, string>());
    }
    public string GET(string endpoint)
    {
        return this.GET(endpoint, new Dictionary<string, string>());
    }
    public string POST(string endpoint, string payload, Dictionary<string, string> headers)
    {
        return this.Perform(WebRequestMethods.Http.Post, TargetHost + endpoint, payload, headers);
    }
    public string POST(string endpoint, Dictionary<string, string> payload, Dictionary<string, string> headers)
    {
        return this.Perform(WebRequestMethods.Http.Post, TargetHost + endpoint, payload, headers);
    }
    public string POST(string endpoint, Dictionary<string, string> payload)
    {
        return this.POST(endpoint, payload, new Dictionary<string, string>());
    }
    public string POST(string endpoint)
    {
        return this.POST(endpoint, new Dictionary<string, string>());
    }

    private string Perform(string method, string url, string jsonPayload, Dictionary<string, string> headers)
    {
        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(url);
        webRequest.Method = method;
        webRequest.ContentType = "application/json";

        foreach (var header in headers)
        {
            webRequest.Headers.Set(header.Key, header.Value);
        }

        if (jsonPayload != string.Empty)
        {
            byte[] requestBytes = Encoding.ASCII.GetBytes(jsonPayload);
            webRequest.ContentLength = requestBytes.Length;
            Stream requestStream = webRequest.GetRequestStream();
            requestStream.Write(requestBytes, 0, requestBytes.Length);
            requestStream.Close();
        }


        var response = (HttpWebResponse)webRequest.GetResponse();
        string json = "";
        using (Stream respStr = response.GetResponseStream())
        {
            using (StreamReader rdr = new StreamReader(respStr, Encoding.UTF8))
            {
                json = rdr.ReadToEnd();
                rdr.Close();
            }
        }

        return json;
    }
    private string Perform(string method, string url, Dictionary<string, string> payload, Dictionary<string, string> headers)
    {
        string payloadString = "";
        if (payload.Count > 0)
            payloadString = JsonConvert.SerializeObject(payload);

        return this.Perform(method, url, payloadString, headers);
    }
}
public class EventObserver
{
    public delegate void Handler(string Event, Dictionary<string, string> Data = null);
    private Dictionary<string, List<Handler>> Handlers { get; set; }

    public EventObserver()
    {
        Handlers = new Dictionary<string, List<Handler>>();
    }
    public EventObserver Subscribe(string EventName, Handler handler)
    {
        if (!Handlers.ContainsKey(EventName))
            Handlers.Add(EventName, new List<Handler>());

        Handlers[EventName].Add(handler);
        return this;
    }
    public void Dispatch(string EventName, Dictionary<string, string> Data = null)
    {
        if (!Handlers.ContainsKey(EventName) || Handlers[EventName].Count == 0)
            return;

        foreach (var handler in Handlers[EventName])
        {
            handler(EventName, Data);
        }
    }
}