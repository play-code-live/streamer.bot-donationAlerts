# Donation dispatch regression — issue #9 follow-up

OAuth was reported working by the maintainer, but a donation publication was visible in the watcher log without a visible Action execution.

The old code reads one ReceiveAsync result as a whole message, ignores EndOfMessage, uses ASCII, silently swallows dispatch exceptions, and discards RunAction's boolean return value. These are confirmed code defects. Whether any of them caused the reported live failure remains to be verified. The provided log appears to omit closing braces; the log rendering may differ from the wire payload.

## Setup

Replace the inline integration.cs in a disposable Streamer.bot configuration, compile and save, then restart the Background Watcher. Reuse the existing valid OAuth tokens. Add simple visible test sub-actions to the named handlers; check Action History as well as the watcher log. Never share OAuth tokens or raw socket messages.

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
        "amount_in_user_currency": 400,
        "is_shown": 0,
        "reason": "default"
      }
    }
  }
}
```

This fixture uses invented IDs and text, but follows the reported payload structure.

## Manual or loopback mock scenarios

| Scenario | Expected |
| --- | --- |
| Complete fixture in one text message | Publication parsed; donation handler entered; daAmount=400, daType=text, daCurrency=RUB, daMessage=Проверка; exactly one primary handler selected. |
| Split the fixture over two or more WebSocket chunks, including a split inside a UTF-8 character | One complete message after EndOfMessage; intact text; one dispatch. |
| Complete donation JSON larger than the 3072-byte receive buffer (under 4 MiB) | Message is assembled across reads; no truncation; one dispatch. |
| Malformed complete JSON, then valid donation | Error at JSON envelope stage; watcher stays alive and processes the following valid donation. |
| Channel join notification, empty control object or unknown channel | No donation action; watcher continues. |
| Null data or zero amount | No donation action; no NullReferenceException. |
| DonationHandler_400 exists | RunAction(name, false) is called and result logged; default not called. |
| DonationHandler_400 absent; DonationHandler_Default exists | Default runs with the original immediate=true behavior. |
| No matching or default handler | Log action not found; no silent failure. |
| Action exists but RunAction returns false | Warning identifies action; no duplicate/fallback primary action. |
| Export or dispatch throws | Processing stage and exception type logged, not raw exception text; subsequent event still processed. |
| DonationHandler_After exists | Existing immediate execution semantics retained. |
| Goal publication and duplicate goal publication | Goal dispatched once; duplicate skipped. |
| Fragmented auth/subscription response | Same complete-message receive helper used; current handshake semantics retained. |
| Binary/close message | Binary ignored in watcher; close follows existing reconnect behavior. |
| Message exceeds 4 MiB | Receive loop reports error and follows existing reconnect path. |

For a mock use only synthetic credentials/IDs and a disposable local configuration; never forward live OAuth traffic to a mock.

## Expected logs on the happy path

- WebSocket message received, bytes=..., chunks=..., type=Text
- Donation publication parsed, id=123
- Donation handler entered, id=123
- Donation arguments exported
- Donation action not found, DonationHandler_400 (only if absent)
- Running donation action, DonationHandler_Default, immediate=True (if default selected)
- Donation action accepted, DonationHandler_Default
- Donation dispatch completed, id=123

RunAction=true means Streamer.bot accepted the operation, not that every sub-action completed. If accepted but nothing happens, inspect Action History, queue and action enablement. The patch intentionally retains the prior specific/default/after execution modes and subscription handshake semantics.
