using System;
using System.Net;
using System.Text;
using System.Web;
using System.Threading.Tasks;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.Net.WebSockets;
using System.Threading;
using System.Security.Cryptography;
using System.Timers;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Globalization;

///----------------------------------------------------------------------------
///   Module:     DonationAlertsIntegration
///   Author:     play_code (https://twitch.tv/play_code)
///   Email:      info@play-code.ru
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
        public void WebError(WebException e, string operation = "HTTP request")
        {
            var response = e.Response as HttpWebResponse;
            if (response == null)
            {
                Error(operation + " failed", e.Status);
                return;
            }

            Error(operation + " failed", e.Status, (int)response.StatusCode, response.StatusCode);
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

    // Keep the event IDs and global variable key from release v0.9.0.
    private const string keyDonationRanges = "da.donation.ranges";
    private const string
        eventConnected = "da.connection.connected",
        eventDisconnected = "da.connection.disconnected",
        eventReconnected = "da.connection.reconnected",
        eventDonationAny = "da.donation.any",
        eventGoalUpdated = "da.goal.updated",
        eventMediaAdd = "da.media.add";

    private readonly object RangeLock = new object();
    private List<KeyValuePair<int, int>> DonationRanges = new List<KeyValuePair<int, int>>();
    private readonly HashSet<string> RegisteredTriggers = new HashSet<string>(StringComparer.Ordinal);
    private const string TextPleaseConnect = "Please connect to DonationAlerts using the Webpage that opened to obtain your token. " +
            "Для продолжения подтвердите авторизацию в появившемся окне браузера";

    public void Init()
    {
        Logger = new PrefixedLogger(CPH);
        Service = new Service(new Client(), Logger);
        SocketService = new SocketService(Service, Logger);
        ConfigureSocketHandlers();

        // Custom triggers are rebuilt by Streamer.bot on every application start.
        RegisterTrigger("DA: Connected", eventConnected, new[] { "DonationAlerts", "Connection" });
        RegisterTrigger("DA: Disconnected", eventDisconnected, new[] { "DonationAlerts", "Connection" });
        RegisterTrigger("DA: Reconnected", eventReconnected, new[] { "DonationAlerts", "Connection" });
        RegisterTrigger("DA: Any donation", eventDonationAny, new[] { "DonationAlerts", "Donations" });
        RegisterTrigger("DA: Goal Updated", eventGoalUpdated, new[] { "DonationAlerts" });
        RegisterTrigger("DA: Media Add", eventMediaAdd, new[] { "DonationAlerts", "Media" });
        RestoreRanges();

        // An update check must not prevent trigger registration.
        try
        {
            CPH.ExecuteMethod("DonationAlert Update Checker", "CheckAndAnnounce");
        }
        catch (Exception e)
        {
            Logger.Error("Update checker failed", e.GetType().Name);
        }
    }

    private void RegisterTrigger(string name, string code, string[] categories)
    {
        try
        {
            if (RegisteredTriggers.Contains(code))
                return;

            if (CPH.RegisterCustomTrigger(name, code, categories))
            {
                RegisteredTriggers.Add(code);
                Logger.Debug("Custom trigger registered", code);
            }
            else
                Logger.Error("Custom trigger registration returned false", code);
        }
        catch (Exception e)
        {
            Logger.Error("Custom trigger registration failed", code, e.GetType().Name);
        }
    }

    public void Dispose()
    {
        // Request cancellation of both watchers; never wait on the Action thread.
        if (SocketService != null)
            SocketService.Close();
    }

    public bool StopDonationCheckerLoop()
    {
        if (SocketService != null)
            SocketService.Stop();
        return true;
    }

    public bool StopMediaCheckerLoop()
    {
        if (SocketService != null)
            SocketService.StopMedia();
        return true;
    }

    public bool CreateAuthLink()
    {
        // Never reuse a code from an earlier authorization attempt.
        CPH.SetGlobalVar("daCode", "", true);
        string authLink = Service.GetAuthLink();
        CPH.SendMessage(TextPleaseConnect);
        System.Diagnostics.Process.Start(authLink);
        Logger.Debug("Opened URL in the default browser. Awaiting for confirmation");

        return Service.ServeAndListenAuth(delegate (string code)
        {
            CPH.SetGlobalVar("daCode", code, true);
            Logger.Debug("Authorization code received");
            return code;
        });
    }
    public bool ObtainAccessToken()
    {
        string code = CPH.GetGlobalVar<string>("daCode");
        if (string.IsNullOrWhiteSpace(code))
        {
            Logger.Debug("Code argument has not arrivied. Make sure you initialized connection for the DA");
            return false;
        }

        // Authorization codes are single-use. A failed exchange needs a new code.
        CPH.SetGlobalVar("daCode", "", true);
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
        if (string.IsNullOrWhiteSpace(refreshToken))
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
    private void RestoreRanges()
    {
        lock (RangeLock)
        {
            try
            {
                string saved = CPH.GetGlobalVar<string>(keyDonationRanges, true);
                if (string.IsNullOrWhiteSpace(saved))
                    return;

                var ranges = JsonConvert.DeserializeObject<List<KeyValuePair<int, int>>>(saved);
                if (ranges == null)
                    return;

                ranges.RemoveAll(range => range.Key < 0 ||
                    (range.Value != -1 && range.Value <= range.Key));
                SortRanges(ranges);
                DonationRanges = ranges;
                RegisterRanges(ranges);
            }
            catch (Exception e)
            {
                Logger.Error("Cannot restore saved donation ranges", e.GetType().Name);
            }
        }
    }

    private static void SortRanges(List<KeyValuePair<int, int>> ranges)
    {
        ranges.Sort((x, y) =>
        {
            int first = x.Key.CompareTo(y.Key);
            return first != 0 ? first : x.Value.CompareTo(y.Value);
        });
    }

    private bool ValidateAndRegisterRanges(string rawRanges)
    {
        var ranges = new List<KeyValuePair<int, int>>();
        foreach (var range in (rawRanges ?? "").Replace(" ", "").Split(','))
        {
            if (string.IsNullOrEmpty(range))
                continue;

            var parts = range.Split('-');
            int from, to;
            if (parts.Length == 1 && int.TryParse(parts[0], out from) && from >= 0)
                ranges.Add(new KeyValuePair<int, int>(from, -1));
            else if (parts.Length == 2 && int.TryParse(parts[0], out from) &&
                int.TryParse(parts[1], out to) && from >= 0 && to >= 0)
            {
                if (from == to)
                    continue;
                if (from > to)
                {
                    int swap = from;
                    from = to;
                    to = swap;
                }
                ranges.Add(new KeyValuePair<int, int>(from, to));
            }
            else
            {
                Logger.Error("Invalid donation range configuration; saved ranges retained");
                return false;
            }
        }

        SortRanges(ranges);
        lock (RangeLock)
        {
            CPH.SetGlobalVar(keyDonationRanges, JsonConvert.SerializeObject(ranges), true);
            DonationRanges = ranges;
            RegisterRanges(ranges);
        }

        return true;
    }

    private static string RangeId(KeyValuePair<int, int> range)
    {
        string from = range.Key.ToString(CultureInfo.InvariantCulture);
        return range.Value == -1 ? from : from + "-" + range.Value.ToString(CultureInfo.InvariantCulture);
    }

    private void RegisterRanges(List<KeyValuePair<int, int>> ranges)
    {
        foreach (var range in ranges)
        {
            string rangeString = RangeId(range);
            RegisterTrigger("DA: Donation (" + rangeString + ")", "da.donation." + rangeString,
                new[] { "DonationAlerts", "Donations" });
        }
    }

    private void EmitTrigger(string eventId)
    {
        if (SocketService == null || SocketService.IsClosed)
            return;

        Logger.Debug("Emitting custom trigger", eventId);
        CPH.TriggerCodeEvent(eventId, true);
        Logger.Debug("Custom trigger emitted", eventId);
    }

    private void TriggerDonationEventBySum(string amountValue)
    {
        decimal amount;
        if (!decimal.TryParse(amountValue, out amount))
        {
            Logger.Error("Invalid donation amount for range matching");
            EmitTrigger(eventDonationAny);
            return;
        }

        // Snapshot is immutable after publishing. Preserve v0.9.0 precedence:
        // exact amount wins, otherwise last matching sorted range, otherwise Any.
        List<KeyValuePair<int, int>> ranges;
        lock (RangeLock)
            ranges = DonationRanges;

        KeyValuePair<int, int>? bestMatch = null;
        foreach (var range in ranges)
        {
            if (range.Value == -1 && amount == range.Key)
            {
                EmitTrigger("da.donation." + RangeId(range));
                return;
            }
            if (range.Value != -1 && amount >= range.Key && amount <= range.Value)
                bestMatch = range;
            else if (amount < range.Key)
                break;
        }

        EmitTrigger(bestMatch.HasValue ? "da.donation." + RangeId(bestMatch.Value) : eventDonationAny);
    }

    public bool MediaCheckerLoop()
    {
        if (SocketService == null || SocketService.IsClosed)
            return false;

        object rawToken;
        if (!args.TryGetValue("daMediaToken", out rawToken) ||
            string.IsNullOrWhiteSpace(rawToken == null ? null : rawToken.ToString()))
            return false;

        return SocketService.StartMediaSocket(rawToken.ToString());
    }

    public bool DonationCheckerLoop()
    {
        if (SocketService == null || SocketService.IsClosed)
            return false;

        // Only overwrite the persisted configuration when the caller supplied daRanges.
        // An explicit empty value still means no amount-specific triggers.
        object rawRanges;
        if (args.TryGetValue("daRanges", out rawRanges) &&
            !ValidateAndRegisterRanges(rawRanges == null ? "" : rawRanges.ToString()))
            return false;

        string accessToken = CPH.GetGlobalVar<string>("daAccessToken");
        if (string.IsNullOrEmpty(accessToken))
        {
            CPH.SendMessage("Необходимо выполнить авторизацию в DonationAlerts. Введите команду !da_connect");
            return false;
        }

        return SocketService.Start(accessToken);
    }

    // Register observers once; the donation and media watchers share this instance.
    private void ConfigureSocketHandlers()
    {
        SocketService
            .On(SocketService.EventStarted, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Ready to connect to the socket");
            })
            .On(SocketService.EventConnected, delegate (string Event, Dictionary<string, string> Data)
            {
                EmitTrigger(eventConnected);
            })
            .On(SocketService.EventAuthorized, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Authorized successfully");
            })
            .On(SocketService.EventReconnected, delegate (string Event, Dictionary<string, string> Data)
            {
                EmitTrigger(eventReconnected);
            })
            .On(SocketService.EventDisconnected, delegate (string Event, Dictionary<string, string> Data)
            {
                EmitTrigger(eventDisconnected);
            })
            .On(SocketService.EventAuthError, delegate (string Event, Dictionary<string, string> Data)
            {
                CPH.SendMessage("Необходимо повторить авторизацию в DonationAlerts. Пожалуйста, введите команду !da_connect");
            })
            .On(SocketService.EventGoalUpdated, delegate (string Event, Dictionary<string, string> Data)
            {
                ExportGoal(Data);
                EmitTrigger(eventGoalUpdated);
            })
            .On(SocketService.EventRecievedDonation, delegate (string Event, Dictionary<string, string> Data)
            {
                Logger.Debug("Donation handler entered", "id=" + Data["id"]);
                ExportDonation(Data);
                TriggerDonationEventBySum(Data["amount"]);
            })
            .On(SocketService.EventMediaAdd, delegate (string Event, Dictionary<string, string> Data)
            {
                foreach (var item in Data)
                    CPH.SetArgument("da.media." + item.Key, item.Value);
                EmitTrigger(eventMediaAdd);
            });
    }

    private void ExportDonation(Dictionary<string, string> Donation)
    {
        string username = "Anonymous";
        if (!string.IsNullOrEmpty(Donation["username"]))
            username = Donation["username"];
        string type = Donation["type"];

        CPH.SetArgument("daName", Donation["name"]);
        CPH.SetArgument("daUsername", username);
        CPH.SetArgument("daType", type);
        if (type == SocketService.DonationData.TypeText)
            CPH.SetArgument("daMessage", Donation["content"]);
        else if (type == SocketService.DonationData.TypeAudio) {
            CPH.SetArgument("daAudioUrl", Donation["content"]);
            CPH.SetArgument("daAudio", SaveFileToTemp(Donation["content"], Donation["id"] + ".wav"));
        }
            
        CPH.SetArgument("daAmount", Donation["amount"]);
        CPH.SetArgument("daCurrency", Donation["currency"]);
        CPH.SetArgument("daAmountConverted", Donation["amount_in_user_currency"]);
    }

    private void ExportGoal(Dictionary<string, string> GoalData)
    {
        CPH.SetArgument("daGoalIsActive", GoalData["is_active"]);
        CPH.SetArgument("daGoalIsDefault", GoalData["is_default"]);
        CPH.SetArgument("daGoalTitle", GoalData["title"]);
        CPH.SetArgument("daGoalCurrency", GoalData["currency"]);
        CPH.SetArgument("daGoalCurrent", GoalData["current"]);
        CPH.SetArgument("daGoalTarget", GoalData["target"]);
    }

    private string SaveFileToTemp(string fileUrl, string name)
    {
        string targetPath = Path.Combine(Path.GetTempPath(), name);
        using (var client = new WebClient())
        {
            client.DownloadFile(fileUrl, targetPath);
        }

        return targetPath;
    }
}

public class SocketService
{
    private const string SocketHost = "wss://centrifugo.donationalerts.com/connection/websocket";
    private const string MediaSocketUrl = "wss://socket1.donationalerts.ru/socket.io/";
    private const string PollingMediaSocketUrl = "https://socket1.donationalerts.ru/socket.io/";
    private const string transportPolling = "polling";
    private const string transportWebSocket = "websocket";

    public const string EventStarted      = "started";
    public const string EventConnected    = "connected";
    public const string EventDisconnected = "disconnected";
    public const string EventReconnected  = "reconnected";
    public const string EventAuthorized   = "authorized";
    public const string EventSubscribed   = "subscribed";
    public const string EventAuthError    = "auth_error"; 

    public const string EventRecievedMessage  = "recieved_message";
    public const string EventRecievedDonation = "recieved_donation";
    public const string EventMediaAdd = "media_add";
    public const string EventGoalUpdated      = "goal_updated";
    private EventObserver Observer { get; set; }
    private Service DaService { get; set; }
    private CPHInline.PrefixedLogger Logger { get; set; }
    private readonly object LifecycleLock = new object();
    private CancellationTokenSource ActiveRun;
    private CancellationTokenSource ActiveMediaRun;
    // v0.9.0 shutdown: retain active sockets so Close can abort them directly.
    // Publish the force-close flag before touching either socket.
    private volatile ClientWebSocket Socket;
    private volatile ClientWebSocket MediaSocket;
    private volatile bool IsForceClosed;
    private readonly string InstanceId = Guid.NewGuid().ToString("N").Substring(0, 8);

    public bool IsClosed { get { return IsForceClosed; } }

    private bool ShouldStop(CancellationToken cancellation)
    {
        return IsForceClosed || cancellation.IsCancellationRequested;
    }

    private void ThrowIfStopping(CancellationToken cancellation)
    {
        if (IsForceClosed)
            throw new OperationCanceledException("Watcher disposed", cancellation);
        cancellation.ThrowIfCancellationRequested();
    }

    // Shutdown logging is best effort: the host logger may already be gone.
    private void LogLifecycle(string message)
    {
        try { Logger.Debug(message, "instance=" + InstanceId); }
        catch (Exception) { }
    }

    private const int BufferSize = 3072;
    private const int MaxSocketMessageSize = 4 * 1024 * 1024;

    private string PreviousGoalEventHash = "";

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
    // Run in the invoking action's context: CPH.SetArgument and
    // TriggerCodeEvent(useArgs: true) depend on that context.
    public bool Start(string accessToken)
    {
        CancellationTokenSource run;
        lock (LifecycleLock)
        {
            if (IsForceClosed)
                return false;
            if (ActiveRun != null)
            {
                Logger.Debug("Background Watcher is already running or stopping");
                return true;
            }

            run = new CancellationTokenSource();
            ActiveRun = run;
        }

        try
        {
            PreviousGoalEventHash = "";
            if (ShouldStop(run.Token))
                return true;
            LogLifecycle("Background Watcher started");
            return RunConnections(accessToken, run.Token);
        }
        finally
        {
            lock (LifecycleLock)
            {
                ActiveRun = null;
                run.Dispose();
            }
            if (!IsForceClosed)
                LogLifecycle("Background Watcher stopped");
        }
    }

    // Manual stop permits a later start, but only after the old run exits.
    public void Stop()
    {
        lock (LifecycleLock)
        {
            try { CancelRun(ActiveRun); }
            finally { AbortSocket(Socket); }
        }
    }

    public void StopMedia()
    {
        lock (LifecycleLock)
        {
            try { CancelRun(ActiveMediaRun); }
            finally { AbortSocket(MediaSocket); }
        }
    }

    private static void AbortSocket(ClientWebSocket socket)
    {
        if (socket == null)
            return;

        // Abort releases a pending connect/read/write. The watcher owns disposal.
        // Do not attempt a graceful CloseAsync handshake on an aborted socket.
        try { socket.Abort(); }
        catch (ObjectDisposedException) { }
        catch (InvalidOperationException) { }
        catch (WebSocketException) { }
    }

    private static void CancelRun(CancellationTokenSource run)
    {
        if (run == null)
            return;

        try { run.Cancel(); }
        catch (ObjectDisposedException) { }
        catch (AggregateException) { }
    }

    // Restore the direct shutdown path from v0.9.0. Do not rely on a
    // WebSocket cancellation callback or call host APIs from Dispose.
    public void Close()
    {
        IsForceClosed = true;
        try
        {
            AbortSocket(Socket);
        }
        finally
        {
            try
            {
                AbortSocket(MediaSocket);
            }
            finally
            {
                // Still cancel HTTP operations and interrupt reconnect delays.
                // No WebSocket Abort callbacks are registered on these tokens.
                lock (LifecycleLock)
                {
                    CancelRun(ActiveRun);
                    CancelRun(ActiveMediaRun);
                }
            }
        }
    }

    private bool RunConnections(string accessToken, CancellationToken cancellation)
    {
        bool isReconnected = false;
        int retryDelay = 1000;
        while (!ShouldStop(cancellation))
        {
            bool receivedMessage = false;
            try
            {
                RunConnection(accessToken, isReconnected, cancellation, ref receivedMessage);
            }
            catch (WebException e)
            {
                var response = e.Response as HttpWebResponse;
                bool unauthorized = response != null && response.StatusCode == HttpStatusCode.Unauthorized;
                if (e.Response != null)
                    e.Response.Close();

                if (ShouldStop(cancellation))
                    return true;

                if (unauthorized)
                {
                    Observer.Dispatch(EventAuthError);
                    return false;
                }

                Logger.Error("WebSocket setup HTTP request failed", e.Status);
            }
            catch (Exception e)
            {
                // Cancellation can surface as OperationCanceledException,
                // WebSocketException or ObjectDisposedException depending on the runtime.
                if (ShouldStop(cancellation))
                    return true;

                Logger.Error("WebSocket connection failed", e.GetType().Name);
            }

            if (ShouldStop(cancellation))
                return true;

            // v0.9.0 kept retrying. Retain that behavior with a bounded
            // backoff and no recursive calls or delay after cancellation.
            isReconnected = true;
            if (receivedMessage)
                retryDelay = 1000;
            if (ShouldStop(cancellation))
                return true;

            Logger.Debug("Waiting before donation socket reconnect", retryDelay);
            if (cancellation.WaitHandle.WaitOne(retryDelay) || ShouldStop(cancellation))
                return true;
            retryDelay = Math.Min(retryDelay * 2, 30000);
        }

        return true;
    }

    private void RunConnection(string accessToken, bool isReconnected,
        CancellationToken cancellation, ref bool receivedMessage)
    {
        ThrowIfStopping(cancellation);
        var userProfile = DaService.GetProfileInfo(accessToken, cancellation);
        if (userProfile == null || string.IsNullOrEmpty(userProfile.SocketConnectionToken))
            throw new InvalidDataException("Missing socket profile");

        ThrowIfStopping(cancellation);
        using (var socket = new ClientWebSocket())
        {
            Socket = socket;
            try
            {
                ThrowIfStopping(cancellation);
                Observer.Dispatch(EventStarted, null);
                socket.ConnectAsync(new Uri(SocketHost), CancellationToken.None).GetAwaiter().GetResult();
                ThrowIfStopping(cancellation);
                Observer.Dispatch(isReconnected ? EventReconnected : EventConnected);

                string socketClientId = ObtainSocketClientId(socket, userProfile.SocketConnectionToken, cancellation);
                var channelInfoList = DaService.ObtainChannelSubscribeToken(accessToken, userProfile.Id, socketClientId, cancellation);
                foreach (var channelInfoItem in channelInfoList)
                {
                    ThrowIfStopping(cancellation);
                    SubscribeToTheChannel(socket, channelInfoItem.Channel, channelInfoItem.Token, cancellation);
                }

                while (!ShouldStop(cancellation) && socket.State == WebSocketState.Open)
                {
                    Logger.Debug("Waiting for a message");
                    WebSocketReceiveResult result;
                    string rawMessage = ReceiveSocketMessage(socket, cancellation, out result);
                    ThrowIfStopping(cancellation);

                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
                        // Acknowledge the peer close, but never block shutdown on it.
                        using (var closeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                        {
                            closeTimeout.CancelAfter(2000);
                            socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, closeTimeout.Token).GetAwaiter().GetResult();
                        }
                        return;
                    }

                    if (result.MessageType == WebSocketMessageType.Text)
                    {
                        receivedMessage = true;
                        ProcessSocketMessage(rawMessage, cancellation);
                    }
                }
            }
            finally
            {
                Socket = null;
            }
        }
    }

    // ReceiveAsync returns a chunk, not necessarily a complete message.
    // Decode UTF-8 only after assembling all chunks, including split multibyte characters.
    private string ReceiveSocketMessage(ClientWebSocket socket, CancellationToken cancellation, out WebSocketReceiveResult result)
    {
        var buffer = new ArraySegment<byte>(new byte[BufferSize]);
        using (var message = new MemoryStream())
        {
            int chunks = 0;
            do
            {
                ThrowIfStopping(cancellation);
                result = socket.ReceiveAsync(buffer, CancellationToken.None).GetAwaiter().GetResult();
                ThrowIfStopping(cancellation);
                if (result.MessageType == WebSocketMessageType.Close)
                    return null;

                chunks++;
                if (message.Length + result.Count > MaxSocketMessageSize)
                    throw new InvalidDataException("WebSocket message exceeds configured limit");

                message.Write(buffer.Array, buffer.Offset, result.Count);
            }
            while (!result.EndOfMessage);

            Logger.Debug("WebSocket message received", "bytes=" + message.Length,
                "chunks=" + chunks, "type=" + result.MessageType);
            if (result.MessageType != WebSocketMessageType.Text)
                return null;

            return Encoding.UTF8.GetString(message.ToArray());
        }
    }

    private void ProcessSocketMessage(string rawMessage, CancellationToken cancellation)
    {
        string stage = "raw event";
        try
        {
            if (ShouldStop(cancellation))
                return;
            Observer.Dispatch(EventRecievedMessage, new Dictionary<string, string> { { "message", rawMessage } });

            // Parse the envelope once. A malformed message must not disconnect the watcher.
            stage = "JSON envelope";
            var envelope = JObject.Parse(rawMessage);
            var result = envelope["result"] as JObject;
            if (result == null)
            {
                if (envelope["error"] != null)
                    Logger.Error("WebSocket protocol error received");
                return;
            }

            var socketMessage = result.ToObject<SocketMessage>();
            var messageType = socketMessage.RecognizeType();
            if (messageType == SocketMessage.TypeUnknown)
                return;

            // Join/leave confirmations have a channel but do not contain a publication.
            var publication = result["data"] as JObject;
            if (publication == null || !(publication["data"] is JObject))
            {
                Logger.Debug("WebSocket channel message has no publication", messageType);
                return;
            }

            switch (messageType)
            {
                case SocketMessage.TypeDonation:
                    stage = "donation deserialization";
                    var donationEvent = result.ToObject<DonationResponse>();
                    if (!donationEvent.IsValid())
                    {
                        Logger.Debug("Donation publication rejected: missing data or non-positive amount");
                        return;
                    }

                    var donation = donationEvent.Data.Donation;
                    Logger.Debug("Donation publication parsed", "id=" + donation.Id);
                    stage = "donation dispatch";
                    if (ShouldStop(cancellation))
                        return;
                    Observer.Dispatch(EventRecievedDonation, donation.ToDictionary());
                    Logger.Debug("Donation dispatch completed", "id=" + donation.Id);
                    break;

                case SocketMessage.TypeGoal:
                    stage = "goal deserialization";
                    var goalEvent = result.ToObject<GoalProgressResponse>();
                    if (!goalEvent.IsValid())
                        return;

                    var goal = goalEvent.Data.GoalData;
                    var goalHash = Helper.GetMD5Hash(goal);
                    if (goalHash == PreviousGoalEventHash)
                    {
                        Logger.Debug("Duplicated goal data arrived. Skipping");
                        return;
                    }

                    stage = "goal dispatch";
                    if (ShouldStop(cancellation))
                        return;
                    Observer.Dispatch(EventGoalUpdated, goal.ToDictionary());
                    PreviousGoalEventHash = goalHash;
                    break;
            }
        }
        catch (Exception e)
        {
            // Exception messages and raw JSON can contain sensitive data.
            if (!ShouldStop(cancellation))
                Logger.Error("WebSocket message processing failed", stage, e.GetType().Name);
        }
    }

    private string ObtainSocketClientId(ClientWebSocket socket, string SocketToken, CancellationToken cancellation)
    {
        ThrowIfStopping(cancellation);
        if (socket.State != WebSocketState.Open)
            throw new Exception("Socket is closed");


        var request = new SocketClientRequest
        {
            Parameters = new SocketClientRequestParams
            {
                Token = SocketToken,
            }
        };
        var payload = JsonConvert.SerializeObject(request);

        socket.SendAsync(
            new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();

        WebSocketReceiveResult result;
        string authMessage = ReceiveSocketMessage(socket, cancellation, out result);
        ThrowIfStopping(cancellation);
        Logger.Debug("Auth response received");
        if (result.MessageType == WebSocketMessageType.Close)
        {
            Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
            throw new IOException("Socket closed during authentication");
        }
        Logger.Debug("Recieved auth message");

        if (authMessage == null)
            throw new InvalidDataException("Expected a text WebSocket auth response");

        var authResponse = JsonConvert.DeserializeObject<SocketClientResponse>(authMessage);
        if (authResponse == null || authResponse.Data == null || string.IsNullOrEmpty(authResponse.Data.Client))
            throw new InvalidDataException("WebSocket auth response has no client identifier");
 
        Observer.Dispatch(EventAuthorized, new Dictionary<string, string> { { "client", authResponse.Data.Client }, { "version", authResponse.Data.Version } });

        return authResponse.Data.Client;
    }
    private void SubscribeToTheChannel(ClientWebSocket socket, string Channel, string ChannelToken, CancellationToken cancellation)
    {
        ThrowIfStopping(cancellation);
        var request = new SubscribeRequest
        {
            Data = new SubscribeRequestData { Channel = Channel, Token = ChannelToken },
        };
        var payload = JsonConvert.SerializeObject(request);
        socket.SendAsync(
            new ArraySegment<byte>(Encoding.UTF8.GetBytes(payload)),
            WebSocketMessageType.Text,
            true,
            CancellationToken.None
        ).GetAwaiter().GetResult();
        Logger.Debug("Subscribe request has been sent");

        for (int i = 0; i < 2; i++)
        {
            WebSocketReceiveResult result;
            string jsonResponse = ReceiveSocketMessage(socket, cancellation, out result);
            ThrowIfStopping(cancellation);
            Logger.Debug("Subscribe response resieved");
            if (result.MessageType == WebSocketMessageType.Close)
            {
                Observer.Dispatch(EventDisconnected, new Dictionary<string, string> { { "description", result.CloseStatusDescription } });
                throw new IOException("Socket closed during subscription");
            }
            if (jsonResponse == null)
                throw new InvalidDataException("Expected a text WebSocket subscribe response");

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

    // Media support restored from the release v0.9.0 source. Keep its
    // Engine.IO 3 polling/upgrade protocol, with an independent cancellation token.
    private string ApplyMediaParameters(string url, string transport, string sid = "", string t = "")
    {
        var queryString = HttpUtility.ParseQueryString(string.Empty);
        queryString.Add("EIO", "3");
        queryString.Add("transport", transport);
        if (!string.IsNullOrEmpty(sid))
            queryString.Add("sid", sid);
        if (!string.IsNullOrEmpty(t))
            queryString.Add("t", t);
        return string.Format("{0}?{1}", url, queryString.ToString());
    }

    private string GenerateT()
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString()));
    }

    private string CleanUpMediaResponseString(string response)
    {
        return response.Trim(new char[] { '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', ':' });
    }

    private MediaSocketResponse GetMediaRules(HttpClient httpClient, string t, CancellationToken cancellation)
    {
        string url = ApplyMediaParameters(PollingMediaSocketUrl, transportPolling, t: t);
        using (var request = new HttpRequestMessage(HttpMethod.Get, url))
        using (var response = httpClient.SendAsync(request, cancellation).GetAwaiter().GetResult())
        {
            response.EnsureSuccessStatusCode();
            string rawJson = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            ThrowIfStopping(cancellation);
            var result = JsonConvert.DeserializeObject<MediaSocketResponse>(CleanUpMediaResponseString(rawJson));
            if (result == null || string.IsNullOrEmpty(result.sid))
                throw new InvalidDataException("Media response has no session identifier");
            Logger.Debug("Media rules fetched");
            return result;
        }
    }

    private void SendMediaPollingPacket(HttpClient httpClient, string sid, string t,
        string packet, CancellationToken cancellation)
    {
        var url = ApplyMediaParameters(PollingMediaSocketUrl, transportPolling, sid, t);
        // Engine.IO 3 polling frames are length-prefixed.
        string payload = packet.Length.ToString(CultureInfo.InvariantCulture) + ":" + packet;
        using (var request = new HttpRequestMessage(HttpMethod.Post, url))
        {
            request.Content = new StringContent(payload, Encoding.UTF8);
            request.Content.Headers.ContentType = MediaTypeHeaderValue.Parse("text/plain;charset=UTF-8");
            using (var response = httpClient.SendAsync(request, cancellation).GetAwaiter().GetResult())
            {
                response.EnsureSuccessStatusCode();
            }
        }
    }

    private void RegisterMediaSocketUser(HttpClient httpClient, string token, string sid, string t,
        CancellationToken cancellation)
    {
        string packet = "42" + JsonConvert.SerializeObject(new object[]
        {
            "add-user", new { token = token, type = "minor" }
        });
        SendMediaPollingPacket(httpClient, sid, t, packet, cancellation);
        Logger.Debug("Media add-user emitted successfully");
    }

    private void SubscribeMediaMessages(HttpClient httpClient, string token, string sid, string t,
        CancellationToken cancellation)
    {
        string packet = "42" + JsonConvert.SerializeObject(new object[]
        {
            "media", new { token = token, message_data = new { action = "get-pause-state", source = "media_widget" } }
        });
        SendMediaPollingPacket(httpClient, sid, t, packet, cancellation);
        Logger.Debug("Media subscribe emitted successfully");
    }

    public bool StartMediaSocket(string mediaToken)
    {
        CancellationTokenSource run;
        lock (LifecycleLock)
        {
            if (IsForceClosed)
                return false;
            if (ActiveMediaRun != null)
            {
                Logger.Debug("Media Watcher is already running or stopping");
                return true;
            }
            run = new CancellationTokenSource();
            ActiveMediaRun = run;
        }

        try
        {
            if (ShouldStop(run.Token))
                return true;
            LogLifecycle("Media Watcher started");
            RunMediaSocket(mediaToken, run.Token);
            return true;
        }
        catch (Exception e)
        {
            if (ShouldStop(run.Token))
                return true;
            Logger.Error("Media Watcher failed", e.GetType().Name);
            return false;
        }
        finally
        {
            lock (LifecycleLock)
            {
                ActiveMediaRun = null;
                run.Dispose();
            }
            if (!IsForceClosed)
                LogLifecycle("Media Watcher stopped");
        }
    }

    private void SendMediaSocketPacket(ClientWebSocket socket, string packet, CancellationToken cancellation)
    {
        ThrowIfStopping(cancellation);
        socket.SendAsync(new ArraySegment<byte>(Encoding.UTF8.GetBytes(packet)),
            WebSocketMessageType.Text, true, CancellationToken.None).GetAwaiter().GetResult();
    }

    private void RunMediaSocket(string mediaToken, CancellationToken cancellation)
    {
        using (var httpClient = new HttpClient())
        {
            string t = GenerateT();
            var mediaData = GetMediaRules(httpClient, t, cancellation);
            RegisterMediaSocketUser(httpClient, mediaToken, mediaData.sid, t, cancellation);
            SubscribeMediaMessages(httpClient, mediaToken, mediaData.sid, t, cancellation);

            string socketUrl = ApplyMediaParameters(MediaSocketUrl, transportWebSocket, mediaData.sid);
            using (var mediaSocket = new ClientWebSocket())
            {
                MediaSocket = mediaSocket;
                try
                {
                    ThrowIfStopping(cancellation);
                    Observer.Dispatch(EventStarted, null);
                    mediaSocket.ConnectAsync(new Uri(socketUrl), CancellationToken.None).GetAwaiter().GetResult();
                    ThrowIfStopping(cancellation);
                    if (mediaSocket.State != WebSocketState.Open)
                        throw new IOException("Media socket did not open");

                    Logger.Debug("Connected to the media socket");
                    SendMediaSocketPacket(mediaSocket, "2probe", cancellation);
                    SendMediaSocketPacket(mediaSocket, "5", cancellation);
                    SendMediaSocketPacket(mediaSocket, "2", cancellation);
                    Logger.Debug("Media initialization flow is done");

                    while (!ShouldStop(cancellation) && mediaSocket.State == WebSocketState.Open)
                    {
                        WebSocketReceiveResult result;
                        string message = ReceiveSocketMessage(mediaSocket, cancellation, out result);
                        ThrowIfStopping(cancellation);
                        if (result.MessageType == WebSocketMessageType.Close)
                        {
                            Logger.Debug("Media socket connection is closed");
                            using (var closeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                            {
                                closeTimeout.CancelAfter(2000);
                                mediaSocket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null,
                                    closeTimeout.Token).GetAwaiter().GetResult();
                            }
                            return;
                        }

                        if (result.MessageType == WebSocketMessageType.Text)
                            ProcessMediaMessage(message, cancellation);

                        if (ShouldStop(cancellation) || mediaSocket.State != WebSocketState.Open)
                            return;
                        SendMediaSocketPacket(mediaSocket, "2", cancellation);
                        if (cancellation.WaitHandle.WaitOne(2000) || ShouldStop(cancellation))
                            return;
                    }
                }
                finally
                {
                    MediaSocket = null;
                }
            }
        }
    }

    private void ProcessMediaMessage(string message, CancellationToken cancellation)
    {
        try
        {
            if (string.IsNullOrEmpty(message) || ShouldStop(cancellation))
                return;
            string rawJson = CleanUpMediaResponseString(message);
            // Ignore Engine.IO probe/pong and Socket.IO control packets.
            if (!rawJson.StartsWith("[", StringComparison.Ordinal))
                return;

            var packet = JArray.Parse(rawJson);
            if (packet.Count < 2 || packet[0].Type != JTokenType.String ||
                (string)packet[0] != "media")
                return;

            var mediaMessage = packet[1].Type == JTokenType.String
                ? JsonConvert.DeserializeObject<MediaSocketMessageMediaMessage>((string)packet[1])
                : packet[1].ToObject<MediaSocketMessageMediaMessage>();
            if (mediaMessage == null || mediaMessage.media == null ||
                string.IsNullOrEmpty(mediaMessage.media.additional_data))
                return;

            var additionalData = JsonConvert.DeserializeObject<MediaAdditionalData>(mediaMessage.media.additional_data);
            if (additionalData == null || ShouldStop(cancellation))
                return;

            Logger.Debug("Media request parsed");
            Observer.Dispatch(EventMediaAdd, new Dictionary<string, string>
            {
                { "title", mediaMessage.media.title },
                { "url", additionalData.url },
                { "video_id", additionalData.video_id },
                { "owner", additionalData.owner },
            });
        }
        catch (Exception e)
        {
            if (!ShouldStop(cancellation))
                Logger.Error("Media message processing failed", e.GetType().Name);
        }
    }

    private class MediaSocketResponse
    {
        public List<string> upgrades;
        public string sid;
        public int pingInterval;
        public int pingTimeout;
    }

    private class MediaSocketMessageMediaMessage
    {
        public string action;
        public MediaSocketMessageMediaInfo media;
    }

    private class MediaSocketMessageMediaInfo
    {
        public int media_id;
        public string user_id;
        public string type;
        public string sub_type;
        public string title;
        public string additional_data;
        public string date_created;
        public int is_played;
        public object date_played;
    }

    private class MediaAdditionalData
    {
        public string video_id;
        public int alert_id;
        public int alert_type;
        public string owner;
        public string url;
        public int start_from;
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
    private class SocketMessage
    {
        public const string TypeDonation = "donation";
        public const string TypeGoal = "goal";
        public const string TypeUnknown = "unknown";

        [JsonProperty("channel")]
        public string Channel { get; set; }
        public string RecognizeType()
        {
            if (!string.IsNullOrEmpty(Channel) && Channel.StartsWith("$alerts:donation_", StringComparison.Ordinal))
            {
                return TypeDonation;
            }
            else if (!string.IsNullOrEmpty(Channel) && Channel.StartsWith("$goals:goal_", StringComparison.Ordinal))
            {
                return TypeGoal;
            }
            else
            {
                return TypeUnknown;
            }
        }
    }
    private class DonationResponse
    {
        [JsonProperty("channel")]
        public string Channel { get; set; }
        [JsonProperty("data")]
        public DonationResponseData Data = new DonationResponseData();

        public bool IsValid()
        {
            return Data != null && Data.Donation != null && Data.Donation.Amount > 0;
        }
    }
    private class DonationResponseData
    {
        [JsonProperty("seq")]
        public int Seq { get; set; }
        [JsonProperty("data")]
        public DonationData Donation = new DonationData();
    }
    public class DonationData
    {
        public const string TypeAudio = "audio";
        public const string TypeText = "text";

        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("name")]
        public string Name { get; set; }
        [JsonProperty("message_type")]
        public string Type { get; set; }
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

        public Dictionary<string, string> ToDictionary() => new Dictionary<string, string>
            {
                { "id", Id.ToString() },
                { "name", Name },
                { "username", UserName },
                { "type", Type },
                { "content", Message },
                { "amount", Amount.ToString() },
                { "currency", Currency },
                { "amount_in_user_currency", AmountInUserCurrency.ToString() },
            };
    }
    private class GoalProgressResponse
    {
        [JsonProperty("channel")]
        public string Channel { get; set; }
        [JsonProperty("data")]
        public GoalProgressData Data = new GoalProgressData();
        public bool IsValid()
        {
            return Data != null && Data.GoalData != null && Data.GoalData.GoalAmount > 0;
        }
    }
    private class GoalProgressData
    {
        [JsonProperty("seq")]
        public int Seq { get; set; }
        [JsonProperty("data")]
        public GoalData GoalData = new GoalData();
    }
    private class GoalData
    {
        [JsonProperty("id")]
        public int Id { get; set; }
        [JsonProperty("is_active")]
        public bool IsActive { get; set; }
        [JsonProperty("is_default")]
        public bool IsDefault { get; set; }
        [JsonProperty("title")]
        public string Title { get; set; }
        [JsonProperty("currency")]
        public string Currency { get; set; }
        [JsonProperty("raised_amount")]
        public double RaisedAmount { get; set; }
        [JsonProperty("goal_amount")]
        public double GoalAmount { get; set; }

        public Dictionary<string, string> ToDictionary()
        {
            return new Dictionary<string, string>
            {
                { "id", Id.ToString() },
                { "is_active", IsActive.ToString() },
                { "is_default", IsDefault.ToString() },
                { "title", Title },
                { "currency", Currency },
                { "current", RaisedAmount.ToString() },
                { "target", GoalAmount.ToString() },
            };
        }
    }
    
}
public class Service
{
    public delegate string HandleCode(string code);

    private const string RedirectUrl = "http://127.0.0.1:8554/donationAlertsRedirectUri/";
    private const string DefaultScope = "oauth-donation-index oauth-user-show oauth-donation-subscribe oauth-goal-subscribe";

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
        bool hasCode = false;
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
                    hasCode = !string.IsNullOrWhiteSpace(code) && string.IsNullOrEmpty(queryDictionary["error"]);
                    if (hasCode)
                        Handler(code);
                    else
                        Logger.Error("OAuth callback did not contain a successful authorization code");

                    string pageData = "<!DOCTYPE html><html><head><title>Интеграция DonationAlerts + Streamer.bot</title><meta charset=\"UTF-8\"><link href=\"https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha2/dist/css/bootstrap.min.css\" rel=\"stylesheet\" integrity=\"sha384-aFq/bzH65dt+w6FI2ooMVUpc+21e0SRygnTpmBvdBgSdnuTN7QbdgL+OapgHtvPp\" crossorigin=\"anonymous\"><style>body{background-color:#111}</style></head><body><div class=\"container text-center mt-5 text-white-50\"><h3>Код авторизации получен</h3><p>Вы можете закрыть эту вкладку</p><iframe src=\"https://player.twitch.tv/?channel=play_code&parent=127.0.0.1\" frameborder=\"0\" allowfullscreen=\"true\" scrolling=\"no\" height=\"378\" width=\"620\"></iframe><hr><p class=\"font-monospace\">Спасибо за использование интеграции!<br>Если вы столкнулись с любыми сложностями или хотите предложить улучшение функционала,<br>воспользуйтесь секцией <strong>Issues</strong> на <a href=\"https://github.com/play-code-live/streamer.bot-donationAlerts/issues/new\">GitHub</a><br>❤️</p></div></body></html>";
                    if (!hasCode)
                    {
                        resp.StatusCode = (int)HttpStatusCode.BadRequest;
                        pageData = "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"></head><body><h3>Авторизация не завершена</h3><p>Повторите подключение в Streamer.bot.</p></body></html>";
                    }
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

        return hasCode;
    }
    public string GetAuthLink()
    {
        string url = Client.TargetHost + EndpointAuthorize;
        return string.Format("{0}?client_id={1}&redirect_uri={2}&scope={3}&response_type=code", url, ClientId, GetEncodedRedirectUri(), HttpUtility.UrlEncode(DefaultScope, Encoding.UTF8));
    }
    public ProfileInfoData GetProfileInfo(string accessToken, CancellationToken cancellation = default(CancellationToken))
    {
        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + accessToken }
        };

        try
        {
            string json = Client.GET(EndpointProfileInfo, new Dictionary<string, string>(), headers, cancellation);
            ProfileInfoResponse profile = JsonConvert.DeserializeObject<ProfileInfoResponse>(json);
            Logger.Debug("Retrieved user profile info", profile.Data.Id);

            return profile.Data;
        }
        catch (WebException e)
        {
            if (!cancellation.IsCancellationRequested)
                Logger.WebError(e);
            throw;
        }
    }
    public TokenResponse ObtainToken(string Code)
    {
        if (string.IsNullOrWhiteSpace(Code))
        {
            Logger.Error("OAuth authorization_code: missing authorization code");
            return null;
        }

        var values = new Dictionary<string, string>
        {
            { "grant_type", "authorization_code" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "code", Code },
            { "redirect_uri", RedirectUrl }
        };

        return RequestToken(values);
    }
    public TokenResponse RefreshToken(string refreshToken)
    {
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            Logger.Error("OAuth refresh_token: missing refresh token");
            return null;
        }

        var values = new Dictionary<string, string>
        {
            { "grant_type", "refresh_token" },
            { "client_id", ClientId },
            { "client_secret", ClientSecret },
            { "refresh_token", refreshToken },
            { "scope", DefaultScope }
        };

        return RequestToken(values, refreshToken);
    }

    private TokenResponse RequestToken(Dictionary<string, string> values, string previousRefreshToken = null)
    {
        string grantType = values["grant_type"];
        try
        {
            string json = Client.POSTForm(EndpointToken, values);
            var tokenData = JsonConvert.DeserializeObject<TokenResponse>(json);
            if (tokenData == null || string.IsNullOrWhiteSpace(tokenData.AccessToken))
            {
                Logger.Error("OAuth " + grantType + ": missing access token in response");
                return null;
            }

            // DonationAlerts may omit the new refresh token during refresh.
            if (string.IsNullOrWhiteSpace(tokenData.RefreshToken))
                tokenData.RefreshToken = previousRefreshToken;

            if (string.IsNullOrWhiteSpace(tokenData.RefreshToken))
            {
                Logger.Error("OAuth " + grantType + ": missing refresh token in response");
                return null;
            }

            Logger.Debug("OAuth " + grantType + ": token response received");
            return tokenData;
        }
        catch (WebException e)
        {
            LogTokenError(grantType, e);
            return null;
        }
        catch (JsonException)
        {
            // JSON exceptions can contain parts of the response, including tokens.
            Logger.Error("OAuth " + grantType + ": invalid JSON token response");
            return null;
        }
    }

    private void LogTokenError(string grantType, WebException e)
    {
        string operation = "OAuth " + grantType;
        Logger.WebError(e, operation);

        // Only log known OAuth error identifiers. Never log the raw body,
        // error_description, request parameters, or exception message.
        using (var response = e.Response as HttpWebResponse)
        {
            if (response == null)
                return;

            try
            {
                using (var stream = response.GetResponseStream())
                {
                    if (stream == null)
                        return;

                    using (var reader = new StreamReader(stream, Encoding.UTF8))
                    {
                        var buffer = new char[4097];
                        int count = reader.ReadBlock(buffer, 0, buffer.Length);
                        if (count == buffer.Length)
                        {
                            Logger.Debug(operation + ": error response exceeds diagnostic limit");
                            return;
                        }

                        var error = JsonConvert.DeserializeObject<OAuthErrorResponse>(new string(buffer, 0, count));
                        switch (error == null ? null : error.Error)
                        {
                            case "invalid_request":
                            case "invalid_client":
                            case "invalid_grant":
                            case "unauthorized_client":
                            case "unsupported_grant_type":
                            case "invalid_scope":
                            case "access_denied":
                            case "server_error":
                            case "temporarily_unavailable":
                                Logger.Error(operation + ": " + error.Error);
                                break;
                            default:
                                Logger.Debug(operation + ": no recognized OAuth error identifier");
                                break;
                        }
                    }
                }
            }
            catch (Exception)
            {
                // Diagnostics are best-effort and must not mask the original failure.
                Logger.Debug(operation + ": error response could not be parsed");
            }
        }
    }

    private class OAuthErrorResponse
    {
        [JsonProperty("error")]
        public string Error { get; set; }
    }

    public List<ChannelSubscribeResponse> ObtainChannelSubscribeToken(string AccessToken, int UserId, string SocketClientId,
        CancellationToken cancellation = default(CancellationToken))
    {
        var request = new ChannelSubscribeRequest
        {
            Client = SocketClientId,
            Channels = new List<string>() { 
                { string.Format("$alerts:donation_{0}", UserId) },
                { string.Format("$goals:goal_{0}", UserId) },
            }
        };
        string payload = JsonConvert.SerializeObject(request);

        var headers = new Dictionary<string, string>
        {
            { "Authorization", "Bearer " + AccessToken }
        };

        try
        {
            var response = Client.POST(EndpointSubscribe, payload, headers, cancellation);
            var channels = JsonConvert.DeserializeObject<Dictionary<string, List<ChannelSubscribeResponse>>>(response);
            if (channels["channels"].Count == 0)
                throw new Exception("Cannot fetch channels and it's tokens");

            return channels["channels"];
        }
        catch (WebException e)
        {
            if (!cancellation.IsCancellationRequested)
                Logger.WebError(e);
            throw;
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

    public string GET(string endpoint, Dictionary<string, string> parameters, Dictionary<string, string> headers,
        CancellationToken cancellation = default(CancellationToken))
    {
        var queryParams = new List<string>();
        foreach (var parameter in parameters)
        {
            queryParams.Add(string.Format("{0}={1}", parameter.Key, parameter.Value));
        }
        endpoint += "?" + String.Join("&", queryParams);
        return this.Perform(WebRequestMethods.Http.Get, TargetHost + endpoint, string.Empty, headers, cancellation: cancellation);
    }
    public string GET(string endpoint, Dictionary<string, string> parameters)
    {
        return this.GET(endpoint, parameters, new Dictionary<string, string>());
    }
    public string GET(string endpoint)
    {
        return this.GET(endpoint, new Dictionary<string, string>());
    }
    public string POST(string endpoint, string payload, Dictionary<string, string> headers,
        CancellationToken cancellation = default(CancellationToken))
    {
        return this.Perform(WebRequestMethods.Http.Post, TargetHost + endpoint, payload, headers, cancellation: cancellation);
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

    public string POSTForm(string endpoint, Dictionary<string, string> payload)
    {
        var fields = new List<string>();
        foreach (var parameter in payload)
        {
            fields.Add(HttpUtility.UrlEncode(parameter.Key, Encoding.UTF8) + "=" +
                HttpUtility.UrlEncode(parameter.Value, Encoding.UTF8));
        }

        return this.Perform(WebRequestMethods.Http.Post, TargetHost + endpoint,
            string.Join("&", fields), new Dictionary<string, string>(), "application/x-www-form-urlencoded");
    }

    private string Perform(string method, string url, string payload, Dictionary<string, string> headers,
        string contentType = "application/json", CancellationToken cancellation = default(CancellationToken))
    {
        cancellation.ThrowIfCancellationRequested();
        HttpWebRequest webRequest = (HttpWebRequest)WebRequest.Create(url);
        webRequest.Method = method;
        webRequest.ContentType = contentType;

        foreach (var header in headers)
        {
            webRequest.Headers.Set(header.Key, header.Value);
        }

        // The watcher's cancellation also interrupts synchronous profile/subscription HTTP.
        using (cancellation.Register(() =>
        {
            try { webRequest.Abort(); }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }))
        {
            cancellation.ThrowIfCancellationRequested();
            if (payload != string.Empty)
            {
                byte[] requestBytes = Encoding.UTF8.GetBytes(payload);
                webRequest.ContentLength = requestBytes.Length;
                using (Stream requestStream = webRequest.GetRequestStream())
                {
                    requestStream.Write(requestBytes, 0, requestBytes.Length);
                }
            }

            using (var response = (HttpWebResponse)webRequest.GetResponse())
            using (Stream respStr = response.GetResponseStream())
            using (StreamReader rdr = new StreamReader(respStr, Encoding.UTF8))
            {
                string body = rdr.ReadToEnd();
                cancellation.ThrowIfCancellationRequested();
                return body;
            }
        }
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

public static class Helper
{
    public static string GetMD5Hash(object obj)
    {
        using (var md5 = MD5.Create())
        {
            var json = JsonConvert.SerializeObject(obj);
            var hashBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(json));
            var sb = new StringBuilder();
            foreach (var b in hashBytes)
            {
                sb.Append(b.ToString("x2"));
            }
            return sb.ToString();
        }
    }
}