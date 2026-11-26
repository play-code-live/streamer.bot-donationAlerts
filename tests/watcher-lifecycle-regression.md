# Donation and Media Watcher lifecycle regression

Both DonationCheckerLoop and MediaCheckerLoop keep independent cancellation sources for HTTP and reconnect delays. Following the maintainer's working v0.9.0 source, each active ClientWebSocket is published in a field. Dispose sets the volatile IsForceClosed flag, calls Abort directly on both sockets (without taking the lifecycle lock first), and then cancels the HTTP/delay tokens. Connect/send/receive use CancellationToken.None as in v0.9.0; aborting the actual socket interrupts them. The connection owner disposes its socket and clears the field in finally. The flag is checked around every operation and before reconnect. Do not issue CloseAsync on a socket already aborted or call Streamer.bot APIs from Dispose. Manual stop cancels and aborts the corresponding run only.

The watcher stays synchronous in the calling Action on its dedicated queue to preserve the v0.9.0 CPH.SetArgument / TriggerCodeEvent(useArgs: true) behavior. The donation reconnect path retries with capped exponential backoff (1–30 seconds), does not recurse, and stops on HTTP 401 or cancellation. Media retains the original one-connection behavior.

## Setup

Replace inline integration.cs in a disposable copy of the v0.9.0 configuration. Compile/save; enable Precompile on Application start. Existing valid tokens may be reused. For manual stop use a separate non-blocking action queue and Execute C# Method on the same inline instance; invoke StopDonationCheckerLoop or StopMediaCheckerLoop. An action queued behind the running watcher cannot stop it.

## Checks

- Start DonationCheckerLoop, wait for Waiting for a message, close Streamer.bot normally; no fresh connection after cancellation, action exits.
- Start MediaCheckerLoop alone, close Streamer.bot normally; polling or receive is interrupted and Media Watcher stopped is logged if logging is still available.
- Start both watchers; Dispose cancels both, regardless of startup order. No reconnect after disposal.
- Stop only donation; media remains active. Stop only media; donation remains active. Restart after stop, one run of each, no accumulating observers. Try duplicate concurrent starts; no additional connection per watcher.
- Stop during donation connect, auth, subscribe, profile GET or token POST; stop during media polling/upgrade/connect/receive/delay. Use synthetic credentials and local test setup.
- Drop donation connection, verify backoff 1–30 seconds, recovery on network return, no tight recursion; cancel during backoff and verify no next attempt.
- Verify 401 results in auth-error notification and no endless retry.
- Verify peer close uses bounded close-output and unexpected donation disconnect reconnects. Check original da.connection.* events, donation/goal/media trigger args, saved range routing and no duplicate observers.
- Recompile with active watchers. Old instance is disposed; new instance restores triggers in Init and only restarts watcher through normal actions.

## Shutdown diagnostics

- Confirm the currently tested v0.9.0 baseline closes normally (maintainer confirmed).
- Compile this branch, start the donation watcher and close while it is waiting for a WebSocket message. Expect the active socket to abort and the loop to exit without reconnect. Repeat on both watchers together and during reconnect delay.
- Stop manually from a separate queue; the watcher should log its normal stopped line and be restartable. Force-closed watchers deliberately avoid CPH lifecycle logging during host disposal so absence of a final log entry is expected.
- If closing still hangs, inspect Streamer.bot shutdown logs or attach a debugger to see whether CPHInline.Dispose and SocketService.Close are reached, and whether the worker is inside a network operation, host API or queue wait. Do not rely solely on host logging from Dispose.
- Confirm the same custom trigger IDs and arguments still work after restart. OAuth, trigger registration, and message parsing have not been changed.

## Known boundary

Host ordering must be verified: if Streamer.bot waits for a running action before calling Dispose, use manual stop on a separate queue. Cancellation cannot forcibly interrupt arbitrary host API calls or synchronous audio downloads already in progress. No runtime/compile verification or media protocol live test was performed here. Release import files are unchanged.

Lifecycle reference: https://docs.streamer.bot/api/csharp/guide/lifecycle-methods
