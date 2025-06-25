// @ts-ignore
import { BetterAuthPlugin } from 'better-auth';
// @ts-ignore
import { InputContext, EndpointContext, Middleware } from 'better-call';
import * as bcrypt from 'bcrypt';

interface PCIDSSPasswordPolicyOptions {
  passwordHistoryCount: number;
  passwordChangeIntervalDays: number;
  inactiveAccountDeactivationDays: number;
  forcePasswordChangeOnFirstLogin: boolean;
}

// Helper function to compare a password with a hash
async function comparePassword(password: string, hash: string): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

export function pciDssPasswordPolicy(options: PCIDSSPasswordPolicyOptions): BetterAuthPlugin {
  return {
    id: 'pci-dss-password-policy',
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === '/auth/change-password',
          handler: async (ctx) => {
            // @ts-ignore
            const { user, input } = ctx;
            const password = input?.password;

            if (!password || !user) {
              return;
            }

            // Password History Check
            if (user.passwordHistory && user.passwordHistory.length > 0) {
              const recentPasswords = user.passwordHistory.slice(0, options.passwordHistoryCount);
              for (const hashedPwd of recentPasswords) {
                if (await comparePassword(password, hashedPwd)) {
                throw new Error(`Password cannot be one of the last ${options.passwordHistoryCount} used passwords.`);
              }
            }
            }
          },
        },
      ],
      after: [
        {
          matcher: (ctx) => ctx.path === '/auth/login' || ctx.path === '/auth/register',
          handler: async (ctx) => {
            // @ts-ignore
            const { user, db } = ctx;
            if (user) {
              // Update lastLoginDate on any login/registration activity
              await db.updateUser(user.id, { lastLoginDate: new Date().toISOString() });

              // Password Change Frequency Check
              if (user.lastPasswordChange && options.passwordChangeIntervalDays > 0) {
                const lastChangeDate = new Date(user.lastPasswordChange);
                const passwordExpiryDate = new Date(lastChangeDate);
                passwordExpiryDate.setDate(passwordExpiryDate.getDate() + options.passwordChangeIntervalDays);

                if (new Date() > passwordExpiryDate) {
                  await db.updateUser(user.id, { forcePasswordChange: true });
                }
              }

              // First-time User Password Change Requirement
              if (options.forcePasswordChangeOnFirstLogin && !user.lastPasswordChange) {
                await db.updateUser(user.id, { forcePasswordChange: true });
              }
            }
          },
        },
        {
          matcher: (ctx) => ctx.path === '/auth/change-password',
          handler: async (ctx) => {
            // @ts-ignore
            const { user, db, input } = ctx;
            const password = input?.password;
            if (user && password) {
              const saltRounds = 10;
              const hashedPassword = await bcrypt.hash(password, saltRounds);
              const newPasswordHistory = [hashedPassword, ...(user.passwordHistory || [])].slice(0, options.passwordHistoryCount);
              await db.updateUser(user.id, {
                passwordHistory: newPasswordHistory,
                lastPasswordChange: new Date().toISOString(),
                forcePasswordChange: false,
              });
            }
          },
        },
      ],
    },
    schema: {
      users: {
        fields: {
          // @ts-ignore
          passwordHistory: { type: 'string', array: true, default: [] },
          // @ts-ignore
          lastPasswordChange: { type: 'date', default: null },
          // @ts-ignore
          forcePasswordChange: { type: 'boolean', default: false },
          // @ts-ignore
          lastLoginDate: { type: 'date', default: null },
        },
      },
    },
  };
}


