# Yii3 Voyti 2FA WebAuthn Changelog

## 1.0.3 - September 2, 2026

- Chg: Contribute method routes through the shared `2fa.methodRoutes` configuration group.

## 1.0.2 - August 30, 2026

- Chg: Use `discouraged` instead of `required` user verification for login assertions.
- Chg: Use the user's profile name (falling back to username) as the WebAuthn registration display name.
- Enh: `WebauthnService::getCreateArgs()` writes the ceremony challenge out by reference, and `register()` accepts a `$challengeOverride`, for a caller with no session continuity across the two legs of the ceremony (e.g. a stateless API bridge).

## 1.0.1 - August 21, 2026

- Chg: Consolidate Bootstrap5 views into `yiirocks/voyti-views-bootstrap5` package.

## 1.0.0 - August 20, 2026

- Initial release.
