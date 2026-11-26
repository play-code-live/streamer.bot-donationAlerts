# Donation and Media Watcher lifecycle regression

Both DonationCheckerLoop and MediaCheckerLoop now have independent cancellation sources. Dispose permanently closes the inline instance and cancels both runs without joining the action threads. Network operations use cancellable socket connect/send/receive, profile/subscription requests, media polling, and cancellation-aware delays. Manual StopDonationCheckerLoop and StopMediaCheckerLoop stop the corresponding run only, allowing a later start after it exits. Observers are configured once at Init.

The watcher stays synchronous in the calling Action to preserve the v0.9.0 CPH.SetArgument / TriggerCodeEvent(useArgs: true) behavior. The donation reconnect path retries with capped exponential backoff (1–30 seconds), does not recurse, and stops on HTTP 401 or cancellation. Media retains the original one-connection behavior.

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

## Known boundary

Host ordering must be verified: if Streamer.bot waits for a running action before calling Dispose, use manual stop on a separate queue. Cancellation cannot forcibly interrupt arbitrary host API calls or synchronous audio downloads already in progress. No runtime/compile verification or media protocol live test was performed here. Release import files are unchanged.

Lifecycle reference: https://docs.streamer.bot/api/csharp/guide/lifecycle-methods
