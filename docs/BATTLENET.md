# Battle.net / World of Warcraft

This branch is an **experimental account and library integration**, not Steam feature parity.
It targets official World of Warcraft Retail, Classic and Classic Era. No private servers.

## Implemented

- Battle.net appears in Settings > Accounts and the library's store filters.
- Sign-in uses Blizzard's own page in an ephemeral native WebKit sheet, including Blizzard's
  password and Authenticator flow. BCD does not implement or store a Blizzard password.
- After sign-in, BCD validates the account portal session against its games API before saving
  secure cookies applicable to that exact account host in `bcd.battlenet.session` in the existing
  device-only Keychain. The session and account replies are never logged or cached on disk.
- Library refresh reads the account's WoW licence and exposes Retail, Classic and Classic Era
  as client choices. These rows do not assert an active subscription, an expansion entitlement,
  server availability, or device compatibility. Duplicate subscriptions produce one set of rows.
- WoW programs already added through Files under `_retail_/Wow.exe`, `_classic_/WowClassic.exe`
  or `_classic_era_/WowClassic.exe` appear under Battle.net, using the existing library entry's
  Play, settings and history. They do not receive the portal's cookies or an automatic login.
- Sign-out deletes the Keychain item and the discovered list, cancels refresh, and prevents late
  requests from restoring the account. Imported entries and files remain.

API requests are bounded and never follow redirects with a Cookie header. If the session expires,
sign in again. Network errors retain the current list. The web sheet has Cancel and Continue;
it deliberately offers no Safari paste flow because an account-page URL is not a credential.

## Still required for the requested Steam use case

1. A native NGDP/CASC install adapter: version/build/CDN selection per WoW flavour and region,
   index/root/encoding/install manifests, BLTE decoding, integrity verification, disk checks,
   resumable install/update/repair, locale selection, and removal through the shared content queue.
2. A verified game authentication flow, distinct from the account portal and public OAuth profile
   APIs. Never pass web cookies, borrow another application's client identity, or embed an OAuth
   client secret to approximate this. Until this exists, players must use the game's own login.
3. iPhone/iPad tests with official WoW builds, subscription accounts, Authenticator/passkeys,
   session expiry, Retail/Classic updates, and the Wine/FEX/rendering path. No WoW compatibility
   or successful login is claimed by this change.
4. Additional Battle.net products, art, account region selection (including China), cloud saves,
   friends/chat and achievement support. None are implied by connecting an account.

Uninstalled Battle.net rows have no Install button while there is no native download driver.
Do not release or describe this branch as full Battle.net support until the above work is tested.

## Protocol references and validation

- [Blizzard's OAuth samples](https://github.com/Blizzard/oauth-client-sample): public profile
  authentication is a separate integration from installing and signing in to games.
- [Galaxy Battle.net backend](https://github.com/FriendsOfGalaxy/galaxy-integration-battlenet/blob/master/src/backend.py)
  and [library mapping](https://github.com/FriendsOfGalaxy/galaxy-integration-battlenet/blob/master/src/plugin.py):
  references for `/api/games-and-subs`, `/api/details`, and WoW title ID 5730135. These are
  undocumented account-portal endpoints, subject to change. The implementation is independently
  written; it does not reuse Galaxy's client ID, secret, tokens or code.

Run `python3 tests/host/check-battlenet.py --require-swift` on a macOS host. It compiles the
Foundation account rules and checks host/cookie isolation, malformed replies, deduplication,
WoW client identification, and credential redaction using synthetic data only. Also run the
existing GOG/content/settings checks after changes to the shared files. A full iOS build and
live device verification require Apple's toolchain; Windows source checks are insufficient.
