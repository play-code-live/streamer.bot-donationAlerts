# Donation and Media Watcher lifecycle regression

## Motivation

The maintainer reproduced the shutdown hang in the original v0.9.0 and after the direct socket-abort fix. The exact Streamer.bot shutdown ordering is unconfirmed. A permanent Action that must finish before its inline code is disposed is a possible dependency cycle. The new implementation removes the never-returning Action from the lifecycle: both public CheckerLoop methods schedule a managed Task.Run and return immediately.

Existing dedicated queues can remain configured. Do not wrap the method call in a separate infinite While sub-action or wait for the task. Both watchers maintain independent cancellation sources and task references and reject duplicate starts until the previous worker has exited. True means start accepted or already running, not that the remote connection is authenticated. Startup values are read on the calling Action before scheduling, and each custom event has a fresh explicit Dictionary<string, object> instead of using that Action's argument stack.

Dispose sets the volatile IsForceClosed flag, aborts both active WebSockets, then cancels HTTP operations and retry delays. It does not wait for the workers to finish or call Streamer.bot APIs. The socket owner disposes it and clears the field in finally. The reconnect loop checks cancellation and the flag before reconnecting. Existing OAuth and message framing are unchanged.

## Setup

Replace the inline integration.cs in the existing v0.9.0 test configuration; compile and save. Enable Precompile on Application start. Use existing credentials and existing action/trigger bindings. No reimport is needed. If the old never-returning Action is stuck, stop it using the existing stop method from a different queue before recompiling. A manual stop uses StopDonationCheckerLoop or StopMediaCheckerLoop on the same inline instance.

## Acceptance tests

- Start the donation watcher. Action History should show its initiating Action completed promptly while the log shows Background Watcher started (background task). It must not remain in the Running state. Wait for Waiting for a message and confirm one synthetic or test donation still triggers the bound Action.
- Confirm the same for the media watcher. If configured, start both together, then close Streamer.bot normally and check that its process exits and no new reconnect is initiated. Repeat with only one watcher, during idle receive and during reconnect delay.
- Rapidly invoke each start repeatedly; only one live task/socket per watcher. Stop each independently and restart after it exits. No duplicate events.
- Validate every previous da.* event ID and documented da* / da.media.* argument, including range selection, goal updates and audio/text donations. Test that two successive events do not share stale arguments. Startup Action arguments (including daMediaToken) are deliberately not copied into the event.
- During a synthetic network outage, check donation reconnect backoff 1–30 seconds and stop during delay. Verify HTTP 401 ends the donation worker and prompts reauthorization, and that starting again is possible after a fresh authorization.
- Recompile while watchers are active. Old instance must stop; new instance registers original trigger IDs on Init. No old worker reconnect.
- Close Streamer.bot with the integration disabled and after calling both stop methods explicitly. If it still hangs even with no running watcher Action, collect host shutdown logs and inspect other actions/integrations or a process dump. This separates the proposed Action-lifecycle mechanism from unrelated shutdown problems.

## Known limits

This change is a new architecture to test, not a confirmed diagnosis of the host hang. Explicit TriggerCodeEvent arguments and Task.Run are documented, but the exact host/version behavior of emitting from a background task needs runtime testing. The public start methods now report scheduling rather than eventual connection success. Arbitrary host API calls or audio downloads already in progress cannot be forcibly interrupted. Compile/runtime verification requires Streamer.bot; release import files are unchanged.

References:
- https://docs.streamer.bot/api/csharp/guide/threading-best-practices
- https://docs.streamer.bot/api/csharp/guide/lifecycle-methods
- https://docs.streamer.bot/api/csharp/methods/core/triggers/trigger-code-event
