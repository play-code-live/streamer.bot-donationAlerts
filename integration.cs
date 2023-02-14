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
    private const double Version = 0.3;
    private const string RepoReleasesAPIEndpoint = "https://api.github.com/repos/play-code-live/streamer.bot-donationAlerts/releases?per_page=100";

    private HttpListener listener = null;
    private ClientWebSocket socket = null;

    private readonly string targetHost = "https://www.donationalerts.com";
    private readonly string socketHost = "wss://centrifugo.donationalerts.com/connection/websocket";

    private readonly string endpointAuthorize = "/oauth/authorize";
    private readonly string endpointToken = "/oauth/token";
    private readonly string endpointProfileInfo = "/api/v1/user/oauth";
    private readonly string endpointSubscribe = "/api/v1/centrifuge/subscribe";

    private readonly string defaultScope = "oauth-donation-index oauth-user-show oauth-donation-subscribe";
    private readonly string redirectUrl = "http://127.0.0.1:8554/donationAlertsRedirectUri/";

    private readonly string handlerActionName = "DonationHandler_Default";

    private const string argsKeyClientId = "daClientId";
    private const string argsKeyClientSecret = "daClientSecret";


    #region Texts
    private readonly string textPleaseConnect = "Please connect to DonationAlerts using the Webpage that opened to obtain your token. " +
            "Для продолжения подтвердите авторизацию в появившемся окне браузера";
    private readonly string textAuthLinkRequirements = "To connect integration you need to specify daClientId and daClientSecret arguments. " +
            "Чтобы начать подключение, вам необходимо указать daClientId и daClientSecret аргументы";
    #endregion

    #region Default Methods
    public void Init()
    {
        var newerVersion = GetNewerGitHubVersion(Version);
        if (newerVersion != null)
            CPH.SendMessage(string.Format("Доступно обновление интеграции с DonationAlerts. Версия {0} - {1}", newerVersion.tag_name, newerVersion.html_url));
    }

    public void Dispose()
    {
        try
        {
            if (this.socket == null)
                return;
            this.socket.Abort();
            this.socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
            this.socket = null;
        }
        catch (Exception) { }
    }
    #endregion

    public bool CreateAuthLink()
    {
        string clientId = args[argsKeyClientId].ToString();
        string clientSecret = args[argsKeyClientSecret].ToString();

        if (clientId == "" || clientSecret == "")
        {
            CPH.SendMessage(this.textAuthLinkRequirements);
            return false;
        }

        CPH.SetGlobalVar(argsKeyClientId, clientId, true);
        CPH.SetGlobalVar(argsKeyClientSecret, clientSecret, true);

        string url = this.targetHost + this.endpointAuthorize;
        string urlRequest = string.Format("{0}?client_id={1}&redirect_uri={2}&scope={3}&response_type=code", url, clientId, this.GetEncodedRedirectUri(), this.defaultScope);
        CPH.SendMessage(this.textPleaseConnect);
        System.Diagnostics.Process.Start(urlRequest);
        CPH.LogDebug("Opened URL in the default browser. Awaiting for confirmation");
        try
        {
            listener = new HttpListener();
            listener.Prefixes.Add(this.redirectUrl);
            listener.Start();
            Task listenTask = HandleIncomingConnections();
            var forceCloseTimer = new System.Timers.Timer(30000);
            forceCloseTimer.Elapsed += this.WebServerForceClose;
            forceCloseTimer.AutoReset = true;
            forceCloseTimer.Enabled = true;
            listenTask.GetAwaiter().GetResult();
            listener.Close();
        }
        catch (WebException e)
        {
            this.Debug(e.Status.ToString());
            return false;
        }

        return true;
    }

    private void WebServerForceClose(Object source, ElapsedEventArgs e)
    {
        this.Debug("Timer invoked");
        if (listener != null && listener.IsListening)
        {
            listener.Close();
            this.Debug("Server has been closed by timeout");
        }
    }

    public bool ObtainAccessToken()
    {
        string clientId = CPH.GetGlobalVar<string>(argsKeyClientId);
        string clientSecret = CPH.GetGlobalVar<string>(argsKeyClientSecret);
        string code = CPH.GetGlobalVar<string>("daCode");
        if (clientId == "" || clientSecret == "" || code == "")
        {
            this.Debug("Some of the required arguments has not arrived. Make sure you initialized connection for the DA");
            return false;
        }


        var values = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "client_id", clientId },
            { "client_secret", clientSecret },
            { "code", code },
            { "redirect_uri", this.redirectUrl }
        };

        string accessToken = "";
        string refreshToken = "";
        try
        {
            string json = this.PerformPOST(this.endpointToken, values);
            this.Debug("Request to the token API has been performed");
            JsonTextReader reader = new JsonTextReader(new StringReader(json));
            while (reader.Read())
            {
                string Path = reader.Path.Replace("[", "").Replace("]", "");
                if ((reader.Value != null) && (reader.TokenType.ToString() != "PropertyName") && (Path == "access_token"))
                {
                    accessToken = reader.Value.ToString();
                }

                if ((reader.Value != null) && (reader.TokenType.ToString() != "PropertyName") && (Path == "refresh_token"))
                {
                    refreshToken = reader.Value.ToString();
                }
            }

            CPH.SetGlobalVar("daAccessToken", accessToken, true);
            CPH.SetGlobalVar("daRefreshToken", refreshToken, true);
            this.Debug("Obtained accessToken and refreshToken successfully");

            return true;
        }
        catch (WebException e)
        {
            var response = (HttpWebResponse)e.Response;
            var statusCodeResponse = response.StatusCode;
            int statusCodeResponseAsInt = ((int)response.StatusCode);
            this.Debug("Obtain token error", "status code", statusCodeResponseAsInt.ToString(), statusCodeResponse);
            return false;
        }
    }

    public bool RefreshAccessToken()
    {
        if (args.ContainsKey("refresh_token_recursion_protection"))
            return false;
        this.Debug("Refreshing access token");
        string clientId = CPH.GetGlobalVar<string>(argsKeyClientId);
        string clientSecret = CPH.GetGlobalVar<string>(argsKeyClientSecret);
        string refreshToken = CPH.GetGlobalVar<string>("daRefreshToken");
        if (clientId == "" || clientSecret == "" || refreshToken == "")
        {
            this.Debug("Some of the required arguments has not arrived. Make sure you initialized connection for the DA");
            return false;
        }

        var values = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "client_id", clientId },
            { "client_secret", clientSecret },
            { "refresh_token", refreshToken },
            { "scope", this.defaultScope }
        };

        string accessToken = "";
        try
        {
            string json = this.PerformPOST(this.endpointToken, values);
            this.Debug("Request to the token API has been performed");
            JsonTextReader reader = new JsonTextReader(new StringReader(json));
            while (reader.Read())
            {
                string Path = reader.Path.Replace("[", "").Replace("]", "");
                if ((reader.Value != null) && (reader.TokenType.ToString() != "PropertyName") && (Path == "access_token"))
                {
                    accessToken = reader.Value.ToString();
                }

                if ((reader.Value != null) && (reader.TokenType.ToString() != "PropertyName") && (Path == "refresh_token"))
                {
                    refreshToken = reader.Value.ToString();
                }
            }

            CPH.SetGlobalVar("daAccessToken", accessToken, true);
            CPH.SetGlobalVar("daRefreshToken", refreshToken, true);
            CPH.SetArgument("refresh_token_recursion_protection", true);

            return true;
        }
        catch (WebException e)
        {
            var response = (HttpWebResponse)e.Response;
            var statusCodeResponse = response.StatusCode;
            int statusCodeResponseAsInt = ((int)response.StatusCode);
            this.Debug("status code : " + statusCodeResponseAsInt.ToString() + " " + statusCodeResponse);
            return false;
        }
    }

    public bool GetProfileInfo()
    {
        this.Debug("Obtaining socket token");
        string accessToken = CPH.GetGlobalVar<string>("daAccessToken");
        if (accessToken == "")
            return false;

        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + accessToken }
        };

        try
        {
            string json = this.PerformGET(this.endpointProfileInfo, new Dictionary<string, string>(), headers);
            ProfileInfoResponse profile = JsonConvert.DeserializeObject<ProfileInfoResponse>(json);
            CPH.SetGlobalVar("daSocketToken", profile.data.socket_connection_token, true);
            CPH.SetGlobalVar("daUserId", profile.data.id, true);
            this.Debug("User ID", profile.data.id, json);

            return true;
        }
        catch (WebException e)
        {
            var response = (HttpWebResponse)e.Response;
            var statusCodeResponse = response.StatusCode;
            int statusCodeResponseAsInt = ((int)response.StatusCode);
            this.Debug("status code : " + statusCodeResponseAsInt.ToString() + " " + statusCodeResponse);
            if (!this.RefreshAccessToken())
                return false;
            return this.GetProfileInfo();
        }
    }

    public ChannelSubscribeResponseItem ObtainPrivateChannelConnectionToken(string socketClientId)
    {
        string accessToken = CPH.GetGlobalVar<string>("daAccessToken");
        int userId = CPH.GetGlobalVar<int>("daUserId");
        if (accessToken == "")
            throw new Exception("Access token not found");
        if (userId == 0)
            throw new Exception("There is no presaved user Id. Try reconnecting the DA integration");

        var payload = "{\"client\":\"" + socketClientId + "\", \"channels\": [\"" + string.Format("[$alerts:donation_{0}]", userId) + "\"]}";

        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + accessToken }
        };

        var response = this.PerformPOST(this.endpointSubscribe, payload, headers);
        var channels = JsonConvert.DeserializeObject<Dictionary<string, List<ChannelSubscribeResponseItem>>>(response);

        if (channels["channels"].Count == 0)
            throw new Exception("Cannot fetch channels and it's tokens");

        CPH.SetGlobalVar("daChannelToken", channels["channels"][0].token, false);
        CPH.SetGlobalVar("daChannel", channels["channels"][0].channel, false);

        this.Debug("Channel connection token recieved", channels["channels"][0].channel);
        return channels["channels"][0];
    }

    public bool DonationCheckerLoop()
    {
        this.ConnectToSocket();
        return true;
    }

    private Task ConnectToSocket(bool isReconnected = false)
    {
        this.socket = new ClientWebSocket();
        this.Debug("Ready to connect to the socket");
        this.socket.ConnectAsync(new Uri(this.socketHost), CancellationToken.None).GetAwaiter().GetResult();
        this.Debug("Connected to the socket");
        CPH.SendMessage("DonationAlert Background Watcher is ON");

        var buf = new ArraySegment<byte>(new byte[1024]);

        if (this.socket.State == WebSocketState.Open)
        {
            string socketClientId = this.ObtainSocketClientId(this.socket);
            var channelInfo = this.ObtainPrivateChannelConnectionToken(socketClientId);
            this.SubscribeToTheChannel(channelInfo.channel, channelInfo.token);
        }

        try
        {
            while (this.socket.State == WebSocketState.Open)
            {
                this.Debug("Waiting for a message");
                var result = this.socket.ReceiveAsync(buf, CancellationToken.None).GetAwaiter().GetResult();
                this.Debug("Message recieved");
                if (result.MessageType == WebSocketMessageType.Close)
                {
                    this.socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                    this.Debug(result.CloseStatusDescription);
                }
                else
                {
                    isReconnected = false;
                    this.Debug("Recieved message");
                    string rawMessage = Encoding.ASCII.GetString(buf.Array, 0, result.Count);
                    this.Debug(rawMessage);
                    try
                    {
                        var donationEvent = JsonConvert.DeserializeObject<Dictionary<string, DonationEvent>>(rawMessage);
                        var donation = donationEvent["result"].data.data;
                        if (!this.IsValidDonation(donation))
                            continue;
                        this.ExportDonation(donation);

                        string targetActionName = string.Format("DonationHandler_{0}", donation.amount);
                        if (CPH.ActionExists(targetActionName))
                        {
                            CPH.RunAction(targetActionName, false);
                        }
                        else if (CPH.ActionExists(this.handlerActionName))
                        {
                            CPH.RunAction(this.handlerActionName);
                        }
                    }
                    catch (Exception e) { }
                }
            }
        }
        catch (Exception e)
        {
            if (isReconnected)
            {
                this.Debug("Cannot reconnect to socket too many times");
                return null;
            }
        }

        return this.ConnectToSocket(true);
    }

    private void SubscribeToTheChannel(string channel, string channelToken)
    {
        var request = "{\"id\":2,\"method\":1,\"params\":{\"channel\":\"" + channel + "\", \"token\":\"" + channelToken + "\"}}";
        this.socket.SendAsync(
            new ArraySegment<byte>(Encoding.ASCII.GetBytes(request)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();
        this.Debug("Subscribe request has been sent");

        var buf = new ArraySegment<byte>(new byte[1024]);

        for (int i = 0; i < 2; i++)
        {
            var result = this.socket.ReceiveAsync(buf, CancellationToken.None).GetAwaiter().GetResult();
            this.Debug("Subscribe response resieved");
            if (result.MessageType == WebSocketMessageType.Close)
            {
                this.socket.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                this.Debug(result.CloseStatusDescription);
                throw new Exception("Socket has closed connection");
            }
            var jsonResponse = Encoding.ASCII.GetString(buf.Array, 0, result.Count);
            this.Debug("Subscribe response", jsonResponse);
            var subscribeResponse = JsonConvert.DeserializeObject<ChannelSocketSubscribeResponse>(jsonResponse);
            if (subscribeResponse.id != 0)
                continue;
            if (subscribeResponse.result.channel != channel)
                throw new Exception("Cannot subscribe to the channel");
            break;
        }

        this.Debug("Subscribed to the channel", channel);
    }

    private string ObtainSocketClientId(ClientWebSocket ws)
    {
        string socketToken = CPH.GetGlobalVar<string>("daSocketToken");
        if (socketToken == string.Empty)
        {
            this.Debug("Socket token is empty. Cannot Perform");
            throw new Exception("Empty socket token");
        }
        var request = "{\"id\":1,\"params\":{\"token\":\"" + socketToken + "\"}}";
        this.Debug("Socket auth request", request);
        this.Debug("accessToken", CPH.GetGlobalVar<string>("daAccessToken"));
        ws.SendAsync(
            new ArraySegment<byte>(Encoding.ASCII.GetBytes(request)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();

        var buf = new ArraySegment<byte>(new byte[1024]);
        var result = ws.ReceiveAsync(buf, CancellationToken.None).GetAwaiter().GetResult();
        this.Debug("Auth response resieved");
        if (result.MessageType == WebSocketMessageType.Close)
        {
            ws.CloseAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
            this.Debug(result.CloseStatusDescription);
            throw new Exception("Socket has closed connection");
        }
        this.Debug("Recieved auth message");
        var authResponse = JsonConvert.DeserializeObject<SocketAuthResponse>(Encoding.ASCII.GetString(buf.Array, 0, result.Count));

        return authResponse.result.client;
    }

    private bool IsValidDonation(DonationData donation)
    {
        return donation.amount > 0;
    }

    private void ExportDonation(DonationData donation)
    {
        string username = "Anonymous";
        if (!string.IsNullOrEmpty(donation.username))
            username = donation.username;

        CPH.SetArgument("daName", donation.name);
        CPH.SetArgument("daUsername", username);
        CPH.SetArgument("daMessage", donation.message);
        CPH.SetArgument("daAmount", donation.amount);
        CPH.SetArgument("daCurrency", donation.currency);
        CPH.SetArgument("daAmountConverted", donation.amount_in_user_currency);
    }

    #region Client Methods
    private string PerformGET(string endpoint, Dictionary<string, string> parameters, Dictionary<string, string> headers)
    {
        var queryParams = new List<string>();
        foreach (var parameter in parameters)
        {
            queryParams.Add(string.Format("{0}={1}", parameter.Key, parameter.Value));
        }
        endpoint += "?" + String.Join("&", queryParams);
        return this.PerformRequest("GET", this.targetHost + endpoint, new Dictionary<string, string>(), headers);
    }
    private string PerformGET(string endpoint, Dictionary<string, string> parameters)
    {
        return this.PerformGET(endpoint, parameters, new Dictionary<string, string>());
    }
    private string PerformGET(string endpoint)
    {
        return this.PerformGET(endpoint, new Dictionary<string, string>());
    }
    private string PerformPOST(string endpoint, string payload, Dictionary<string, string> headers)
    {
        return this.PerformRequest("POST", this.targetHost + endpoint, payload, headers);
    }
    private string PerformPOST(string endpoint, Dictionary<string, string> payload, Dictionary<string, string> headers)
    {
        return this.PerformRequest("POST", this.targetHost + endpoint, payload, headers);
    }
    private string PerformPOST(string endpoint, Dictionary<string, string> payload)
    {
        return this.PerformPOST(endpoint, payload, new Dictionary<string, string>());
    }
    private string PerformPOST(string endpoint)
    {
        return this.PerformPOST(endpoint, new Dictionary<string, string>());
    }

    private string PerformRequest(string method, string url, string jsonPayload, Dictionary<string, string> headers)
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
        var statusCodeResponse = response.StatusCode;
        this.Debug("status code : " + statusCodeResponse);
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
    private string PerformRequest(string method, string url, Dictionary<string, string> payload, Dictionary<string, string> headers)
    {
        string payloadString = "";
        if (payload.Count > 0)
            payloadString = JsonConvert.SerializeObject(payload);


        return this.PerformRequest(method, url, payloadString, headers);
    }
    #endregion

    #region Helpers and system methods
    private string GetEncodedRedirectUri()
    {
        return HttpUtility.UrlEncode(this.redirectUrl);
    }

    private async Task HandleIncomingConnections()
    {
        bool runServer = true;
        while (runServer)
        {
            this.Debug("Server Waiting ...");
            HttpListenerContext context = await listener.GetContextAsync();
            HttpListenerRequest request = context.Request;
            HttpListenerResponse resp = context.Response;
            var queryDictionary = HttpUtility.ParseQueryString(request.Url.Query);
            string code = queryDictionary["code"];
            CPH.SetGlobalVar("daCode", code, true);
            string pageData = "<!DOCTYPE><html><head><title>DONATION ALERTS TO STREAMER.BOT</title></head><body>Success! You can close this window</body></html>";
            byte[] data = Encoding.UTF8.GetBytes(String.Format(pageData));
            resp.ContentType = "text/html";
            resp.ContentEncoding = Encoding.UTF8;
            resp.ContentLength64 = data.LongLength;
            await context.Response.OutputStream.WriteAsync(data, 0, data.Length);
            this.Debug("code : " + code);
            resp.Close();
            runServer = false;
            listener.Close();
        }
    }
    #endregion

    #region Logs
    private void Debug(string message, params Object[] additional)
    {
        string finalMessage = message;
        foreach (var line in additional)
        {
            finalMessage += ", " + line;
        }
        this.Debug(finalMessage);
    }
    private void Debug(string message)
    {
        message = string.Format("-- {0}: {1}", "Donation Alerts", message);
        CPH.LogDebug(message);
    }
    #endregion

    public class ChannelSubscribeResponseItem
    {
        public string channel;
        public string token;
    }

    public class ChannelSocketSubscribeResponse
    {
        public int id;
        public ChannelSocketSubscribeResponseBody result;
    }

    public class ChannelSocketSubscribeResponseBody
    {
        public bool recoverable = false;
        public int seq = 0;
        public int type;
        public string channel;
    }

    public class SocketAuthResponse
    {
        public int id;
        public SocketAuthParamResult result;
    }

    public class SocketAuthParamResult
    {
        public string client;
        public string version;
    }

    public class ProfileInfoResponse
    {
        public ProfileInfo data;
    }

    public class ProfileInfo
    {
        public int id;
        public string code;
        public string name;
        public string avatar;
        public string email;
        public string socket_connection_token;
    }

    public class DonationEvent
    {
        public string channel { get; set; }
        public DonationItem data = new DonationItem();
    }

    public class DonationItem
    {
        public int seq;
        public DonationData data = new DonationData();
    }

    public class DonationData
    {
        public int id;
        public string name;
        public string username;
        public string message;
        public double amount;
        public string currency;
        public double amount_in_user_currency;
    }

    public GitHubReleaseResponse GetNewerGitHubVersion(double currentVersion)
    {
        var newer = this.FetchLatestGitHubVersion();
        if (newer == null)
            return null;

        var numbericVersion = Convert.ToDouble(newer.tag_name.Substring(1).Replace('.', ','));
        if (currentVersion >= numbericVersion)
            return null;

        return newer;
    }

    public GitHubReleaseResponse FetchLatestGitHubVersion()
    {
        try
        {
            var releases = this.GetGitHubReleaseVersionsAsync();
            foreach (var release in releases)
            {
                if (release.draft || release.prerelease)
                    continue;

                return release;
            }
        } catch (Exception e)
        {
            this.Debug("Cannot fetch versions of integration. Error: " + e.Message);
            throw e;
        }

        return null;
    }

    private List<GitHubReleaseResponse> GetGitHubReleaseVersionsAsync()
    {
        try
        {
            WebClient webClient = new WebClient();
            webClient.Headers.Add("User-Agent", "StreamerBot DA Integration");
            Uri uri = new Uri(RepoReleasesAPIEndpoint);
            string releases = webClient.DownloadString(uri);

            return JsonConvert.DeserializeObject<List<GitHubReleaseResponse>>(releases);
        } catch (Exception)
        {
        }
        return new List<GitHubReleaseResponse>();
    }

    public class GitHubReleaseResponse
    {
        public string html_url { get; set; }
        public string tag_name { get; set; }
        public string name { get; set; }
        public bool prerelease { get; set; }
        public bool draft { get; set; }
    }
}