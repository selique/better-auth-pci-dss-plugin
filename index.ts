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
    id: "pci-dss-password-policy",
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === "/auth/change-password",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, input, adapter } = ctx;
            const password = input?.password;

            if (!password || !user) {
              return;
            }

            // Buscar histórico de senhas da tabela dedicada
            const passwordHistory = await adapter.findMany({
              model: "pciPasswordHistory",
              where: [{ field: "userId", value: user.id }],
              limit: options.passwordHistoryCount,
              orderBy: [{ field: "createdAt", direction: "desc" }],
            });

            // Password History Check
            if (passwordHistory && passwordHistory.length > 0) {
              for (const historyEntry of passwordHistory) {
                if (
                  await comparePassword(password, historyEntry.passwordHash)
                ) {
                  throw new Error(
                    `Password cannot be one of the last ${options.passwordHistoryCount} used passwords.`
                  );
                }
              }
            }
          },
        },
      ],
      after: [
        {
          matcher: (ctx) =>
            ctx.path === "/auth/login" || ctx.path === "/auth/register",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, adapter } = ctx;
            if (user) {
              // Update lastLoginDate - usando uma tabela separada para metadados não sensíveis
              await adapter.updateOne({
                model: "pciUserMetadata",
                where: [{ field: "userId", value: user.id }],
                update: { lastLoginDate: new Date().toISOString() },
                upsert: {
                  userId: user.id,
                  lastLoginDate: new Date().toISOString(),
                  forcePasswordChange: false,
                },
              });

              // Buscar metadados do usuário
              const userMetadata = await adapter.findOne({
                model: "pciUserMetadata",
                where: [{ field: "userId", value: user.id }],
              });

              // Password Change Frequency Check
              if (
                userMetadata?.lastPasswordChange &&
                options.passwordChangeIntervalDays > 0
              ) {
                const lastChangeDate = new Date(
                  userMetadata.lastPasswordChange
                );
                const passwordExpiryDate = new Date(lastChangeDate);
                passwordExpiryDate.setDate(
                  passwordExpiryDate.getDate() +
                    options.passwordChangeIntervalDays
                );

                if (new Date() > passwordExpiryDate) {
                  await adapter.updateOne({
                    model: "pciUserMetadata",
                    where: [{ field: "userId", value: user.id }],
                    update: { forcePasswordChange: true },
                  });
                }
              }

              // First-time User Password Change Requirement
              if (
                options.forcePasswordChangeOnFirstLogin &&
                !userMetadata?.lastPasswordChange
              ) {
                await adapter.updateOne({
                  model: "pciUserMetadata",
                  where: [{ field: "userId", value: user.id }],
                  update: { forcePasswordChange: true },
                  upsert: {
                    userId: user.id,
                    forcePasswordChange: true,
                    lastLoginDate: new Date().toISOString(),
                  },
                });
              }
            }
          },
        },
        {
          matcher: (ctx) => ctx.path === "/auth/change-password",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, adapter, input } = ctx;
            const password = input?.password;
            if (user && password) {
              const saltRounds = 10;
              const hashedPassword = await bcrypt.hash(password, saltRounds);

              // Salvar no histórico de senhas (tabela dedicada)
              await adapter.create({
                model: "pciPasswordHistory",
                data: {
                  userId: user.id,
                  passwordHash: hashedPassword,
                  createdAt: new Date().toISOString(),
                },
              });

              // Manter apenas o número necessário de entradas no histórico
              const allHistory = await adapter.findMany({
                model: "pciPasswordHistory",
                where: [{ field: "userId", value: user.id }],
                orderBy: [{ field: "createdAt", direction: "desc" }],
              });

              if (allHistory.length > options.passwordHistoryCount) {
                const toDelete = allHistory.slice(options.passwordHistoryCount);
                for (const entry of toDelete) {
                  await adapter.delete({
                    model: "pciPasswordHistory",
                    where: [{ field: "id", value: entry.id }],
                  });
                }
              }

              // Atualizar metadados do usuário
              await adapter.updateOne({
                model: "pciUserMetadata",
                where: [{ field: "userId", value: user.id }],
                update: {
                  lastPasswordChange: new Date().toISOString(),
                  forcePasswordChange: false,
                },
                upsert: {
                  userId: user.id,
                  lastPasswordChange: new Date().toISOString(),
                  forcePasswordChange: false,
                  lastLoginDate: new Date().toISOString(),
                },
              });
            }
          },
        },
      ],
    },
    schema: {
      // Tabela dedicada para histórico de senhas (dados sensíveis)
      pciPasswordHistory: {
        fields: {
          // @ts-ignore
          id: { type: "string", required: true },
          // @ts-ignore
          userId: {
            type: "string",
            required: true,
            references: {
              model: "user",
              field: "id",
              onDelete: "cascade",
            },
          },
          // @ts-ignore
          passwordHash: { type: "string", required: true },
          // @ts-ignore
          createdAt: { type: "date", required: true },
        },
      },
      // Tabela para metadados não sensíveis do usuário
      pciUserMetadata: {
        fields: {
          // @ts-ignore
          id: { type: "string", required: true },
          // @ts-ignore
          userId: {
            type: "string",
            required: true,
            unique: true,
            references: {
              model: "user",
              field: "id",
              onDelete: "cascade",
            },
          },
          // @ts-ignore
          lastPasswordChange: { type: "date", default: null },
          // @ts-ignore
          forcePasswordChange: { type: "boolean", default: false },
          // @ts-ignore
          lastLoginDate: { type: "date", default: null },
          // @ts-ignore
          createdAt: { type: "date", required: true },
          // @ts-ignore
          updatedAt: { type: "date", required: true },
        },
      },
    },
  };
}


