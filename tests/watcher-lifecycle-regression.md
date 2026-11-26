# Background Watcher lifecycle regression

The previous DonationCheckerLoop occupied the invoking Action indefinitely, and the socket loop could recursively reconnect even after Dispose() aborted the socket. Socket operations used CancellationToken.None. These defects are confirmed in code; the exact host shutdown ordering must be verified in Streamer.bot.

The watcher remains synchronous in the invoking action context to preserve CPH.SetArgument and RunAction behavior. The method now returns when the active run is cancelled. Dispose permanently closes the instance; StopDonationCheckerLoop requests cancellation without disabling future starts. The cancellation token reaches connect/send/receive, reconnect delay, profile GET and subscription POST. Cancellation does not wait for the worker in Dispose. A fresh run is allowed only after the previous run exits. The host must actually call Dispose during shutdown; if it waits for the current action before doing so, the manual stop below is a workaround and an event-based architecture may be needed.

References: https://docs.streamer.bot/api/csharp/guide/lifecycle-methods and https://docs.streamer.bot/api/csharp/methods/core/actions/run-action

## Setup

Update the inline integration.cs, compile and save, restart the watcher with existing valid tokens. If the previous version prevents recompilation or exit, fully stop the old Streamer.bot process first, after saving settings. Do not test with live streams.

For manual stop: create an action in a **separate non-blocking queue**, add Execute C# Method pointing to the same named inline C# instance and choose StopDonationCheckerLoop. Optionally bind !da_stop. It must not wait behind the long-running watcher action. The existing release import files are unchanged.

## Checks

- Start watcher, wait for Waiting for a message, close Streamer.bot normally. Expect the old action to exit, no new connection attempt, and the application to close. Check elapsed time and whether Background Watcher stopped is logged when logging is still available.
- Call StopDonationCheckerLoop while the watcher is waiting for a message. The active action completes; no reconnect.
- Run !da_start again after stop; one connection, one execution per test donation. Repeat stop/start.
- Invoke !da_start concurrently; at most one watcher per compiled inline instance; duplicate call returns without adding handlers.
- Stop during connect, socket auth, subscription send/receive, profile GET, or channel-token POST using a synthetic loopback test setup with only dummy credentials. Expect cancellation, no fresh attempt, and no stuck network wait.
- Drop the network without manual stop. Expect a bounded 1-second reconnect delay and at most one failed retry without receiving another text message; a working reconnection resumes delivery.
- Stop during reconnect delay; no subsequent connection.
- Force a profile or subscription HTTP 401; expect auth error notification and no endless retries.
- Peer sends WebSocket Close; close output is bounded, then reconnect if not cancelled.
- Recompile while idle; Dispose cancels the old instance; restart only one watcher.
- Send donations before and after reconnect and manual restart; verify args and primary/default/after behavior is unchanged.

## Known boundary

The watcher cannot forcibly interrupt user-defined inline donation actions already executing, synchronous audio-file downloads, or a host API call blocked inside Streamer.bot. Do not join the action thread in Dispose. If the host waits for the running action before invoking Dispose, stop via the separate action and collect shutdown logs; a future migration to a detached task with explicit custom event arguments would require changing the installed Action configuration. No runtime/compile verification in Streamer.bot has been performed here.
