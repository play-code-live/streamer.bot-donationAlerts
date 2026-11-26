# Donation and custom trigger regression — v0.9.0

The maintainer supplied the actual v0.9.0 source. The previously tracked main and develop sources used legacy named Actions instead of the released custom triggers. The branch now restores the original trigger IDs, names, categories and arguments while retaining the OAuth, WebSocket assembly and cancellation fixes.

## Setup

Replace the existing inline integration.cs in a disposable copy of the v0.9.0 Streamer.bot configuration. Save and compile. Check **Precompile on Application start** on the Execute C# Code sub-action that owns the integration. Use the existing actions/trigger bindings; do not re-import an older release. Existing valid OAuth credentials can be retained. For controlled network failures use only dummy credentials and loopback fixtures.

## Trigger registration

| Trigger label | Code event ID | Category below Custom |
| --- | --- | --- |
| DA: Connected | da.connection.connected | DonationAlerts / Connection |
| DA: Disconnected | da.connection.disconnected | DonationAlerts / Connection |
| DA: Reconnected | da.connection.reconnected | DonationAlerts / Connection |
| DA: Any donation | da.donation.any | DonationAlerts / Donations |
| DA: Goal Updated | da.goal.updated | DonationAlerts |
| DA: Media Add | da.media.add | DonationAlerts / Media |
| DA: Donation (400) | da.donation.400 | DonationAlerts / Donations |
| DA: Donation (100-500) | da.donation.100-500 | DonationAlerts / Donations |

## Synthetic fixture

```json
{
  "result": {
    "channel": "$alerts:donation_123",
    "data": {
      "seq": 5,
      "data": {
        "id": 123,
        "name": "Donations",
        "username": "Тестер",
        "message": "Проверка",
        "message_type": "text",
        "amount": 400,
        "currency": "RUB",
        "amount_in_user_currency": 400
      }
    }
  }
}
```

## Regression scenarios

- Restart with no active OAuth session or watcher: all six base triggers are present after Init, when precompile is enabled.
- Start DonationCheckerLoop with daRanges="100-500,400,500-1000"; stop and restart Streamer.bot. Range triggers are restored from persisted da.donation.ranges during Init, before authorization or the watcher. Names and event IDs remain unchanged; existing actions still point to them.
- Start watcher without daRanges: retain saved ranges. Start with an explicitly empty daRanges: clear routing configuration (previous menu entries can remain registered until restart). Invalid daRanges: warn and preserve saved configuration.
- Complete fixture in one message, then split over several receives, including a split UTF-8 character and a message larger than 3072 bytes: exactly one donation publication per message, intact args and correct trigger.
- Test exact 400 with daRanges above: only da.donation.400. Test 250: only da.donation.100-500. Test 500: only da.donation.500-1000 (last matching sorted range). Test 50: only da.donation.any. Test 250.50: range match, not an integer conversion exception. Any is the historical fallback, not an additional event.
- On a valid donation, args include daName, daUsername, daType, daMessage (text) or daAudioUrl and daAudio (audio), daAmount, daCurrency, daAmountConverted as before. Test text, anonymous, and audio separately.
- Test goal changes and duplicate goals: da.goal.updated with the previous daGoal* argument contract, unchanged goals skipped.
- Test malformed JSON followed by a valid publication, unknown/control messages, null data, zero amount: watcher continues and does not emit an invalid donation.
- Stop/start and reconnect: one observer per event; no duplicate events from accumulating handlers.
- Check logs: Custom trigger registered, Donation publication parsed, Donation handler entered, Emitting custom trigger, Custom trigger emitted. Emitting a trigger does not prove a bound Action ran; inspect Action History and trigger/action enabled state.
- Media: v0.9.0 polling and WebSocket upgrade still work; media event produces da.media.add with da.media.title, da.media.url, da.media.video_id, da.media.owner. Verify both string and object Socket.IO payloads using synthetic messages. No media token/session ID/raw packet in changed logs.
- Media without a daMediaToken argument returns false rather than throwing; it does not depend on starting the donation watcher first.

## References

- https://docs.streamer.bot/guide/core/triggers
- https://docs.streamer.bot/api/csharp/methods/core/triggers/register-custom-trigger
- https://docs.streamer.bot/api/triggers/custom/code-event

No Streamer.bot runtime or compiler test was performed here. These scenarios need to be run against the installed version. No release import files were rebuilt.
