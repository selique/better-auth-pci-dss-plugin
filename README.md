# Better Auth: PCI DSS Password Policy Plugin

A community plugin for [Better Auth](https://better-auth.dev) that enforces advanced password security policies compliant with PCI DSS (Payment Card Industry Data Security Standard) v4.0.

This plugin focuses on features not typically covered by standard authentication libraries, such as password history and expiration policies. For basic policies like password length, complexity, and account lockout, you should use the native options provided by Better Auth itself.

## Features

-   **Password History:** Prevent users from reusing their recent passwords.
-   **Password Expiration:** Force users to change their passwords periodically.
-   **First-Login Password Change:** Force new users to change their password on their first login.
-   **Inactive Account Deactivation:** Includes an endpoint to identify and handle inactive accounts.

## Installation

```bash
npm install better-auth-pci-dss-plugin bcrypt
# or
yarn add better-auth-pci-dss-plugin bcrypt
```

You also need to install `bcrypt` as it is a peer dependency used for secure password hashing for the history feature.

## Usage

Integrate the plugin into your Better Auth configuration.

```typescript
// In your Better Auth setup file (e.g., /lib/auth.ts)

import { betterAuth } from 'better-auth';
import { pciDssPasswordPolicy } from 'better-auth-pci-dss-plugin';

export const auth = betterAuth({
  // ... other Better Auth configurations
  // NATIVE better-auth options for length, complexity, and lockout
  password: {
    minPasswordLength: 12,
    // ... other native password rules
  },
  rateLimit: {
      // ... native rate limit (lockout) rules
  },

  plugins: [
    // ... other plugins
    pciDssPasswordPolicy({
      passwordHistoryCount: 4,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    }),
  ],
});
```

## Configuration Options

| Option                            | Type      | Default | Description                                                                 |
| --------------------------------- | --------- | ------- | --------------------------------------------------------------------------- |
| `passwordHistoryCount`            | `number`  | `4`     | Number of recent passwords to store and prevent reuse.                      |
| `passwordChangeIntervalDays`      | `number`  | `90`    | Number of days after which a password must be changed.                      |
| `inactiveAccountDeactivationDays` | `number`  | `90`    | Number of days of inactivity before an account is considered for deactivation. |
| `forcePasswordChangeOnFirstLogin` | `boolean` | `true`  | If `true`, new users must change their password on first login.             |

## Database Schema

This plugin extends your user table. You must ensure your database adapter (e.g., via migrations) adds the following fields to your `users` table:

-   `passwordHistory` (TEXT[] or JSON) - Stores an array of recent hashed passwords.
-   `lastPasswordChange` (TIMESTAMPTZ) - The date of the last password change.
-   `forcePasswordChange` (BOOLEAN) - A flag to force a password change.
-   `lastLoginDate` (TIMESTAMPTZ) - The date of the user's last successful login.

The plugin will attempt to add these via the Better Auth schema migration system.

## Deactivating Inactive Accounts

The plugin exposes a `POST` endpoint at `/pci-dss/deactivate-inactive-accounts`. You can call this endpoint (e.g., via a cron job) to find inactive users. Note that the endpoint currently only identifies users and does not perform any action. You will need to modify the handler in `index.ts` to implement your desired deactivation logic (e.g., setting an `isActive` flag).

## Contributing

Contributions are welcome! Please feel free to submit a pull request. Note that the tests for this project need to be updated.

## License

This project is licensed under the MIT License. 