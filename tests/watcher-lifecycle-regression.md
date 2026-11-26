# Donation and Media Watcher lifecycle regression

Both DonationCheckerLoop and MediaCheckerLoop now have independent cancellation sources. Dispose sets a volatile shutdown flag before taking the lifecycle lock or cancelling I/O, and cancels both runs without joining the action threads. The flag is checked before connection/reconnection, around receive, during dispatch, and before/after retry delays. Cancellation is still required to unblock a pending network read. Network operations use cancellable socket connect/send/receive, profile/subscription requests, media polling, and cancellation-aware delays. Manual StopDonationCheckerLoop and StopMediaCheckerLoop stop the corresponding run only, allowing a later start after it exits. Observers are configured once at Init.

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

The start, stop and Dispose log lines carry an anonymous instance ID so we can distinguish old/new inline instances. The relative order of the stop and Dispose-finished messages is not guaranteed. Do not share raw event payloads or credentials.

- Start the donation watcher and record its `Background Watcher started, instance=...` line.
- Close Streamer.bot while the watcher is waiting for an event. Look for `Dispose entered: shutdown flag set` with the same instance ID, `Dispose finished: cancellation callbacks returned or failed`, and `Background Watcher stopped`. No new reconnect attempt should start after the shutdown flag is observed.
- If no Dispose-entered line exists (and logging is still active), the host may be waiting for the long-running Action before calling Dispose, or disposing another instance. Check shutdown logs and compare instance IDs. A dedicated queue does not establish shutdown ordering.
- If Dispose-entered is present but Dispose-finished is missing, examine cancellation callbacks / the lifecycle lock. If both are present but the watcher-stopped line is absent, check which blocking operation the watcher was in.
- Call StopDonationCheckerLoop from a different queue, confirm the long-running Action ends, and close the application. This isolates the shutdown problem from the event dispatch path.

## Known boundary

Host ordering must be verified: if Streamer.bot waits for a running action before calling Dispose, use manual stop on a separate queue. Cancellation cannot forcibly interrupt arbitrary host API calls or synchronous audio downloads already in progress. No runtime/compile verification or media protocol live test was performed here. Release import files are unchanged.

Lifecycle reference: https://docs.streamer.bot/api/csharp/guide/lifecycle-methods
