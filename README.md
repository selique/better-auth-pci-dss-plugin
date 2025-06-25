# Better Auth: PCI DSS Password Policy Plugin

> ⚠️ **Development Status**: This plugin is currently in active development and may have compatibility issues with some versions of Better Auth. The plugin has been tested with basic functionality but may require additional testing in production environments. Use with caution and thoroughly test in your specific setup before deploying to production.

A community plugin for [Better Auth](https://better-auth.dev) that enforces advanced password security policies compliant with PCI DSS (Payment Card Industry Data Security Standard) v4.0.

This plugin focuses on features not typically covered by standard authentication libraries, such as password history and expiration policies. For basic policies like password length, complexity, and account lockout, you should use the native options provided by Better Auth itself.

## Features

-   **Password History:** Prevent users from reusing their recent passwords (securely hashed with bcrypt).
-   **Password Expiration:** Force users to change their passwords periodically.
-   **First-Login Password Change:** Force new users to change their password on their first login.
-   **Inactive Account Tracking:** Tracks user login dates for inactive account management.

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
    requireLowercase: true,
    requireUppercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
  },
  rateLimit: {
    // ... native rate limit (lockout) rules
    window: 900, // 15 minutes
    max: 5, // max attempts
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

## How It Works

### Password History
When a user changes their password via `/auth/change-password`, the plugin:
1. Checks if the new password matches any of the last N passwords (configurable)
2. Uses bcrypt to securely compare against stored hashed passwords
3. Stores the new password hash in the history (keeping only the most recent N passwords)

### Password Expiration
On login or registration, the plugin:
1. Checks if the user's last password change was more than N days ago
2. If expired, sets `forcePasswordChange: true` on the user
3. Your frontend should check this flag and redirect to password change

### First-Login Password Change
For new users (those without a `lastPasswordChange` date):
1. Sets `forcePasswordChange: true` on first login
2. Your frontend should handle this flag appropriately

## Database Schema

This plugin extends your user table. You must ensure your database adapter (e.g., via migrations) adds the following fields to your `users` table:

-   `passwordHistory` (TEXT[] or JSON) - Stores an array of recent hashed passwords.
-   `lastPasswordChange` (TIMESTAMPTZ) - The date of the last password change.
-   `forcePasswordChange` (BOOLEAN) - A flag to force a password change.
-   `lastLoginDate` (TIMESTAMPTZ) - The date of the user's last successful login.

The plugin will attempt to add these via the Better Auth schema migration system.

## Frontend Integration

Check the `forcePasswordChange` flag in your user object and redirect accordingly:

```typescript
// Example frontend check
if (user?.forcePasswordChange) {
  // Redirect to password change page
  router.push('/change-password');
}
```

## Inactive Account Management

The plugin tracks the `lastLoginDate` field on users, which you can use to implement your own inactive account deactivation logic. For example:

```typescript
// Example: Find inactive users
const cutoffDate = new Date();
cutoffDate.setDate(cutoffDate.getDate() - 90); // 90 days ago

const inactiveUsers = await db.getUsers({
  where: {
    lastLoginDate: { lt: cutoffDate.toISOString() },
  },
});

// Implement your deactivation logic
for (const user of inactiveUsers) {
  await db.updateUser(user.id, { isActive: false });
}
```

## Security Features

- **Secure Password Storage**: All password history is stored using bcrypt hashing (never plaintext)
- **No Password Exposure**: The plugin never logs or exposes passwords in any form
- **Configurable History**: Limit password history to prevent excessive storage

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

## Development

### Testing

This plugin includes basic unit tests that verify the plugin configuration and structure. The tests use Jest and focus on ensuring the plugin is properly configured.

For more comprehensive integration testing with Better Auth, you can use the [@better-auth-kit/tests](https://www.better-auth-kit.com/docs/libraries/tests) utility library:

```bash
npm install --save-dev @better-auth-kit/tests
```

This library provides utilities to create test instances of Better Auth with your plugins for more realistic testing scenarios.

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License. 