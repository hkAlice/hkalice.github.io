---
title: "The Blind Spot in Warp Terminal’s Network Monitor"
date: 2026-03-31 20:07:11 -0300
categories: [reverse-engineering, security]
tags: [reverse-engineering, network, telemetry, privacy, graphql, rust]
draft: false
mermaid: false
---

Recently, I gave [Warp terminal](https://www.warp.dev/) a shot for curiosity. While the AI aspect of it was unappealing to me, it was developed in Rust and boasts fast boot time, and a decent pre-configured development environment.

With privacy concerns, it offers a built-in "network monitor log" described as letting the user view *all* communications to external servers for transparency. Yet it doesn't; the output is heavily trimmed, and has a systematic blind spot for critical, user-sensitive data.

The binary is bundled with API keys in plaintext. Network logs include stable identifiers (e.g. Firebase UIDs) that are not anonymized, while the network log hides packets from the user.

A RudderStack identifier (`rl_anonymous_id`) is issued via cookies during standard API responses, **independent of explicit telemetry settings**. The value appears to be rotated rather than strictly persistent.

## Tooling

All analysis was performed using the tools below.

- Windows 11
- Warp `v0.2026.03.25.08.24.stable_05` (sha1: `0bf33c5461095cd9b89040c1bc4938f6ff23bb7b`)
- Ghidra
- `strings`
- Cutter
- `frida`
- ProcMon
- Wireshark

Every telemetry option disabled (`Help improve Warp`, `Send crash reports`, `Store AI conversations in the cloud`, `AI`). Settings sync is on.

## Runtime Analysis

### Warp Network Monitor logging

Warp’s network monitor does not capture WebSocket (RTC) traffic, despite claiming to log all external communications. This excludes a primary GraphQL subscription channel used for real-time state updates, which continues to transmit user-associated data even when telemetry and AI features are disabled.

This breaks user trust, as it creates a blind spot for communications not surfaced to the user, despite the claim that the network monitor "allows you to view **all** communications from Warp to external servers to ensure you feel comfortable [...]".

![Warp terminal's network log console description](/assets/img/posts/warp/warp_network_log_claim.png)

The above is a *completeness claim*, which contradicts the actual behaviour. The network monitor provides visibility into request/response traffic, but not into the persistent subscription channel that carries the majority of real-time state updates.

### Hidden state subscription system

The RTC call to `GetWarpDriveUpdates`, hidden from the network monitor, is a 12kb packet that defines state, demonstrably a non-trivial packet that **contains direct user identifiers (UIDs), user profile data (including e-mail), access control structures, and workflow metadata**, being hidden from the user.

```
permissions {
  guests {
    accessLevel
    subject {
      ... UserGuest { firebaseUid }
      ... PendingUserGuest { email }
      ... TeamGuest { uid }
    }
  }
  anyoneLinkSharing { accessLevel }
  space { uid type }
}
```

As seen above, *e-mail addresses of other collaborators* may also be transmitted through this packet. The structure represents an ACL model, essentially a live object graph, and multi-user/organization features are baked in, and propagated through the *same subscription* via RTC.

Additionally, the AI model, which is included even if AI is off, includes fields that may *reveal private workflow information*, such as `workingDirectory`, `PullRequestArtifact.url` and `branch`.

Certain history actions are also bundled, and while not directly considered *telemetry*, it can still be seen as activity tracking:

```
history {
  actions {
    BundledActions | SingleAction
  }
}
```

There are also several fields for a time-versioned event system: `latestTimestamp`, `oldestTimestamp`, `processedAtTimestamp`, `metadataLastUpdatedTs`, `revisionTs` and `taskUpdatedTs`.

This is all data that, in theory, could be used to correlate users, collaborators, and workflow context across systems (e.g team user names, e-mails with repository URL, branch).

### Incomplete redaction of identifiers

While methods to censor auth tokens are present, it often leaks stable, personal identifiers such as Firebase UIDs and RudderStack UGC key, associated with a user.

Since these logs are accessible locally in `\Warp\data\logs`, this enables correlation of activity across requests and systems.

![Secret redaction setting in Warp terminal](/assets/img/posts/warp/secret_redaction.png)

The setting `Secret redaction` was also enabled for this, showing that there is personal information that can be used to identify a user, not being redacted.

### Window focus requests

These requests are triggered by a passive UI event (window focus), not by explicit user action or feature use: `GetRequestLimitInfo`, `GetFeatureModelChoices`, `GetCloudEnvironmentsQuery`, `UserGithubInfo`. This includes a **RudderStack cookie refresh** under `rl_anonymous_id`.

`UserGithubInfo` is issued on every window focus, even when GitHub is not connected. The query requests repository metadata (`installedRepos`) when available. This query occurs even with no GitHub integration configured, implying the check is unconditional rather than user-driven.

`GetRequestLimitInfo` and other AI-related queries are still made despite AI being explicitly off. `"x-oz-api-source": "CLOUD_MODE"` is also included in the header, implying that cloud-backed features are active at the request layer regardless of user-facing AI settings.

### Settings sync

Settings and sync are modelled as server-side objects, tied to a user identity. They require an authenticated user context with a persistent identity (via Firebase), are not purely local toggles, and centrally stored.

`BulkCreateObjects` is responsible for sending client setting changes to the server. Note that `owner.uid` denominates a raw Firebase user ID (masked). In this example, the AI option was set to off (`Global_IsAnyAIEnabled`).

```json
{
    "body": {
        "operationName": "BulkCreateObjects",
        "query": "mutation BulkCreateObjects(...) { bulkCreateObjects { ... }} [TRUNCATED]",
        "variables": {
            "input": {
                "genericStringObjects": {
                    "objects": [
                        {
                            "clientId": "Client-b928c526-74b5-4884-88e6-47c03285b5a4",
                            "format": "JsonPreference",
                            "serializedModel": {
                                "storage_key": "IsAnyAIEnabled",
                                "value": false,
                                "platform": "Global"
                            },
                            "uniquenessKey": {
                                "key": "Global_IsAnyAIEnabled",
                                "uniquePer": "User"
                            }
                        }
                    ],
                    "owner": {
                        "uid": "l5bKRgoCRMXO2****Vz53",
                        "type": "User"
                    }
                    [...truncated...]

```

However, for synchronizing settings *from* the cloud, the server provides a path for the client to override the toggles, including *telemetry options*.

The server-side schema includes a `telemetrySettings { forceEnabled }` field, indicating that telemetry policy can be centrally controlled. Whether this is actively used to override client preferences is not directly observable from client-side analysis alone.

Specifically, `GetWorkspacesMetadataForUser` also details payment information, `telemetryDataCollectionPolicy`, `ugcDataCollectionPolicy`, team member e-mails, AI settings, among other fields.

## Static Analysis

### Extracted strings

Below are strings extracted from the binary, along with a short explanation.

- `https://releases.warp.dev` - Warp update server
- `wss://sessions.app.warp.dev` - WSS session share feature
- `https://warpianwzlfqdq.dataplane.rudderstack.com` - **RudderStack** telemetry entry
- `2uBazVfcqYBDYSOHnqSVx4******` - RudderStack ingestion key
- `IzaSyBdy3O3S9hrdayLJxJ7mriBR4q******` - Public Google API key (`AIzaSyBdy3O3S9hrdayLJxJ7mriBR4qgU******`)
- `https://app.warp.dev/graphql/v2` - Main API, most GraphQL lands here
- `wss://rtc.app.warp.dev/graphql/v2` - RTC for GraphQL, same as HTTP
- `https://oz.warp.dev` - AI and agentic API
- `https://******1da0714f55a93ee4624825f9ec@o540343.ingest.sentry.io/5658526` - Sentry DSN (public identifier for crash reporting ingestion).

Other interesting findings for the purpose of reverse-engineering.

- `protobuf`, `gRpC`
- Merkle field names: `total_sync_duration`, `flushed_node_count`, `flushed_fragment_count`, `total_fragment_size_bytes`, `cache_population_error`, `file_traversal_duration`, `merkle_tree_parse_duration`
- Rust-related: `ai\src\telemetry.rs`, `ui\src\app_focus_telemetry.rs`, `alloc::boxed::Box<dyn warp_core::telemetry::TelemetryContextProvider>`.

### Registry artifacts

Warp also relies heavily on registry for its Windows build.
Here is a dump of keys and values found in `[HKEY_CURRENT_USER\Software\Warp.dev\Warp]`.

Some values were anonymized or in brevity:

- `ExperimentId` can be used to persist user correlation (ID)
- `EnteredAgentModeNumTimes`, `AgentModeSetupBannerShownForRepoPaths` tracks usage pattern as well as repositories
- `MCPExecutionPath` in particular was just a mirror of $PATH.

```
  ExperimentId (String) = 79147d64-bfc2-xxxx-xxxx-3b021525a4d9
  TelemetryEnabled (String) = false
  CrashReportingEnabled (String) = false
  CloudConversationStorageEnabled (String) = false
  ShouldAddAgentModeChip (String) = false
  HasInitializedDefaultSecretRegexes (String) = true
  FontSize (String) = 16.0
  InputBoxTypeSetting (String) = "Universal"
  NLDInTerminalEnabled (String) = true
  IsSettingsSyncEnabled (String) = true
  AvailableLLMs (String) = { ... }
  DidNonAnonymousUserLogIn (String) = true
  DidShowOzLaunchModal (String) = true
  AIRequestLimitInfo (String) = { ... }
  AIRequestQuotaInfoSetting (String) = { ... }
  HasAutoOpenedWelcomeFolder (String) = true
  SystemTheme (String) = false
  Theme (String) = "Dark"
  HasAutoOpenedConversationList (String) = true
  ReceivedReferralTheme (String) = "Inactive"
  AIAssistantRequestLimitInfo (String) = { ... }
  MCPExecutionPath (String) = $PATH
  EnteredAgentModeNumTimes (String) = 0
  WelcomeTipsFeaturesUsed (String) = [{"Action":"SplitPane"},{"Hint":"BlockAction"},{"Hint":"CreateBlock"},{"Hint":"BlockSelect"}]
  AliasExpansionBannerSeen (String) = true
  SafeModeEnabled (String) = true
  OverrideOpacity (String) = 100
  OverrideBlurTexture (String) = false
  NotebookFontSize (String) = 14.0
  Spacing (String) = "Normal"
  ChangelogVersions (String) = {"v0.2026.02.18.08.22.stable_02":true}
  DismissedCodeToolbeltNewFeaturePopup (String) = true
  FontName (String) = "Hack"
  AIFontName (String) = "Hack"
  MatchAIFont (String) = false
  Notifications (String) = {"mode":"Enabled","is_long_running_enabled":true,"long_running_threshold":{"secs":30,"nanos":0},"is_password_prompt_enabled":true,"is_agent_task_completed_enabled":true,"is_needs_attention_enabled":true,"play_notification_sound":true}
  OpenWindowsAtCustomSize (String) = false
  AutosuggestionAcceptedCount (String) = 2
  AgentModeSetupBannerShownForRepoPaths (String) = ["C:\\Data\\Dev\\...\\git"]
  PSPath (String) = Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Warp.dev\Warp
  PSParentPath (String) = Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Warp.dev
  PSChildName (String) = Warp
  PSDrive (PSDriveInfo) = HKCU
  PSProvider (ProviderInfo) = Microsoft.PowerShell.Core\Registry
```

## Key Functions

The following is a description of the RTC WSS chain and offsets found that were used for reverse-engineering.

- Literal: 0x14932C874 (RVA 0x932C874) = `wss://rtc.app.warp.dev/graphql/v2`
- Direct refs: 0x141B19514, 0x141B1951B in FUN_141B19400 (RVA 0x1B19400)
- Caller path: __scrt_common_main_seh -> FUN_141B19680 (RVA 0x1B19680) -> FUN_141B1EE00
- Config copy sink: FUN_14671D540 (RVA 0x671D540) copies struct to globals
- WSS globals: DAT_150B81058 (ptr, RVA 0x10B81058), DAT_150B81060 (len, RVA 0x10B81060)
- Getter: FUN_14671C9C0 (RVA 0x671C9C0)
- Hot sites: read 0x142B7255E (RVA 0x2B7255E), write 0x142B72581 (RVA 0x2B72581)
- Dynamic parser: FUN_14671DF60 (RVA 0x671DF60, handles ws_server_url keys)

## Lessons Learned

Warp’s architecture relies on persistent identity, server-synchronized state, and real-time subscriptions.

While these are not inherently problematic, the network monitor’s incomplete visibility undermines its stated goal of transparency, making it difficult for users to independently verify the full scope of data being transmitted. Users relying on the network monitor as a trust mechanism should be aware of this blind spot.
