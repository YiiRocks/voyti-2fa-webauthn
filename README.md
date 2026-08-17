# Voyti 2FA — WebAuthn Method

WebAuthn / passkey two-factor authentication method for [Voyti](https://github.com/YiiRocks/voyti), the Yii3 user-management extension. Uses a client-collected credential (security key, platform authenticator, or passkey) rather than a typed code, and renders its own login-confirmation fragment.

[![Packagist Version](https://img.shields.io/packagist/v/yiirocks/voyti-2fa-webauthn.svg)](https://packagist.org/packages/yiirocks/voyti-2fa-webauthn)
[![PHP from Packagist](https://img.shields.io/packagist/php-v/yiirocks/voyti-2fa-webauthn.svg)](https://php.net/)
[![Packagist](https://img.shields.io/packagist/dt/yiirocks/voyti-2fa-webauthn.svg)](https://packagist.org/packages/yiirocks/voyti-2fa-webauthn)
[![GitHub License](https://img.shields.io/github/license/yiirocks/voyti-2fa-webauthn.svg)](https://github.com/yiirocks/voyti-2fa-webauthn/blob/main/LICENSE.md)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/yiirocks/voyti-2fa-webauthn/build.yml?branch=main)](https://github.com/yiirocks/voyti-2fa-webauthn/actions)

Stats for Nerds

[![Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyiirocks%2Fvoyti-2fa-webauthn%2Fbadges%2Fcoverage.json)](https://github.com/yiirocks/voyti-2fa-webauthn/tree/badges)
[![MSI](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyiirocks%2Fvoyti-2fa-webauthn%2Fbadges%2Fmsi.json)](https://github.com/yiirocks/voyti-2fa-webauthn/tree/badges)
[![Tests](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyiirocks%2Fvoyti-2fa-webauthn%2Fbadges%2Ftests.json)](https://github.com/yiirocks/voyti-2fa-webauthn/tree/badges)
[![Assertions](https://img.shields.io/endpoint?url=https%3A%2F%2Fraw.githubusercontent.com%2Fyiirocks%2Fvoyti-2fa-webauthn%2Fbadges%2Fassertions.json)](https://github.com/yiirocks/voyti-2fa-webauthn/tree/badges)

## Overview

A two-factor **method** package for Voyti's [voyti-2fa](https://github.com/YiiRocks/voyti-2fa) base. Install it and it registers itself — its button appears on the settings screen's method switcher and it becomes selectable in the login confirmation step. It stores enrolled credentials in its own `user_webauthn_credential` table (migration path registered automatically).

## Installation

The `yiirocks/voyti-2fa` base is pulled in automatically as a dependency:

```bash
composer require yiirocks/voyti-2fa-webauthn
```

## Documentation

The complete reference guide is available at [Yii.Rocks](https://www.yii.rocks/voyti/two-factor/).
