// @ts-ignore
import { BetterAuthPlugin } from 'better-auth';
// @ts-ignore
import { InputContext, EndpointContext, Middleware } from 'better-call';
import * as bcrypt from 'bcrypt';

interface SecurityLogger {
  info: (message: string, meta?: any) => void;
  warn: (message: string, meta?: any) => void;
  error: (message: string, meta?: any) => void;
}

interface SecurityAlert {
  threshold: number;
  timeWindow: string; // e.g., '15 minutes', '1 hour'
  action: "log" | "alert" | "block";
  callback?: (event: SecurityEvent) => void;
}

interface SecurityEvent {
  type: string;
  userId: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
}

interface DataRetentionPolicy {
  passwordHistory?: {
    retainCount: number;
    maxAge?: string; // e.g., '2 years'
  };
  auditLogs?: {
    retainPeriod: string;
    cleanupInterval?: string;
  };
}

interface SecurityMetrics {
  trackFailedAttempts?: boolean;
  trackPasswordChanges?: boolean;
  trackHistoryViolations?: boolean;
  trackForceChanges?: boolean;
}

interface PCIDSSPasswordPolicyOptions {
  passwordHistoryCount: number;
  passwordChangeIntervalDays: number;
  inactiveAccountDeactivationDays: number;
  forcePasswordChangeOnFirstLogin: boolean;

  // 🔐 Security Enhancements
  security?: {
    logger?: SecurityLogger;
    alerts?: {
      passwordHistoryViolations?: SecurityAlert;
      multipleFailedAttempts?: SecurityAlert;
      massPasswordChanges?: SecurityAlert;
    };
    dataRetention?: DataRetentionPolicy;
    metrics?: SecurityMetrics;
    auditTrail?: boolean;
    rateLimit?: {
      enabled: boolean;
      maxAttempts: number;
      windowMs: number;
    };
  };
}

// Default no-op logger
const defaultLogger: SecurityLogger = {
  info: () => {},
  warn: () => {},
  error: () => {},
};

// Helper function to parse time window to milliseconds
function parseTimeWindow(timeWindow: string): number {
  const matches = timeWindow.match(/(\d+)\s*(minute|hour|day)s?/i);
  if (!matches) return 0;

  const value = parseInt(matches[1]);
  const unit = matches[2].toLowerCase();

  switch (unit) {
    case "minute":
      return value * 60 * 1000;
    case "hour":
      return value * 60 * 60 * 1000;
    case "day":
      return value * 24 * 60 * 60 * 1000;
    default:
      return 0;
  }
}

// Helper function to compare a password with a hash
async function comparePassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

// Security event tracker
class SecurityEventTracker {
  private events: Map<string, SecurityEvent[]> = new Map();
  private logger: SecurityLogger;

  constructor(logger: SecurityLogger = defaultLogger) {
    this.logger = logger;
  }

  trackEvent(event: SecurityEvent): void {
    const key = `${event.type}:${event.userId}`;
    const events = this.events.get(key) || [];
    events.push(event);
    this.events.set(key, events);

    // Log the event
    this.logger.info(`Security event: ${event.type}`, {
      userId: event.userId,
      timestamp: event.timestamp,
      ipAddress: event.ipAddress,
      userAgent: event.userAgent,
      metadata: event.metadata,
    });
  }

  checkAlert(eventType: string, userId: string, alert: SecurityAlert): boolean {
    const key = `${eventType}:${userId}`;
    const events = this.events.get(key) || [];

    const windowMs = parseTimeWindow(alert.timeWindow);
    const cutoff = Date.now() - windowMs;

    const recentEvents = events.filter(
      (event) => new Date(event.timestamp).getTime() > cutoff
    );

    if (recentEvents.length >= alert.threshold) {
      this.logger.warn(`Security alert triggered: ${eventType}`, {
        userId,
        eventCount: recentEvents.length,
        threshold: alert.threshold,
        timeWindow: alert.timeWindow,
      });

      if (alert.callback) {
        alert.callback({
          type: eventType,
          userId,
          timestamp: new Date().toISOString(),
          metadata: { eventCount: recentEvents.length },
        });
      }

      return true;
    }

    return false;
  }

  cleanup(): void {
    // Clean up old events (keep last 24 hours)
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;

    for (const [key, events] of this.events.entries()) {
      const filtered = events.filter(
        (event) => new Date(event.timestamp).getTime() > cutoff
      );

      if (filtered.length === 0) {
        this.events.delete(key);
      } else {
        this.events.set(key, filtered);
      }
    }
  }
}

export function pciDssPasswordPolicy(
  options: PCIDSSPasswordPolicyOptions
): BetterAuthPlugin {
  const security = options.security || {};
  const logger = security.logger || defaultLogger;
  const eventTracker = new SecurityEventTracker(logger);

  // Setup periodic cleanup if retention policies are configured
  if (security.dataRetention) {
    setInterval(() => {
      eventTracker.cleanup();
    }, parseTimeWindow(security.dataRetention.auditLogs?.cleanupInterval || "1 hour"));
  }

  return {
    id: "pci-dss-password-policy",
    hooks: {
      before: [
        {
          matcher: (ctx) => ctx.path === "/auth/change-password",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, input, adapter, request } = ctx;
            const password = input?.password;

            if (!password || !user) {
              return;
            }

            try {
              // 🔐 Security Enhancement: Track password change attempt
              const securityEvent: SecurityEvent = {
                type: "password_change_attempt",
                userId: user.id,
                timestamp: new Date().toISOString(),
                ipAddress:
                  request?.headers?.get?.("x-forwarded-for") ||
                  (request as any)?.ip ||
                  undefined,
                userAgent: request?.headers?.get?.("user-agent") || undefined,
              };

              if (security.metrics?.trackPasswordChanges) {
                eventTracker.trackEvent(securityEvent);
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
                    // 🔐 Security Enhancement: Track password history violation
                    const violationEvent: SecurityEvent = {
                      type: "password_history_violation",
                      userId: user.id,
                      timestamp: new Date().toISOString(),
                      ipAddress:
                        request?.headers?.get?.("x-forwarded-for") ||
                        (request as any)?.ip ||
                        undefined,
                      userAgent:
                        request?.headers?.get?.("user-agent") || undefined,
                    };

                    if (security.metrics?.trackHistoryViolations) {
                      eventTracker.trackEvent(violationEvent);
                    }

                    // Check for alerts
                    if (security.alerts?.passwordHistoryViolations) {
                      eventTracker.checkAlert(
                        "password_history_violation",
                        user.id,
                        security.alerts.passwordHistoryViolations
                      );
                    }

                    // 🔐 Security Enhancement: Secure error message (no sensitive details)
                    logger.warn("Password history violation detected", {
                      userId: user.id,
                      timestamp: new Date().toISOString(),
                    });

                    throw new Error(
                      `Password cannot be one of the last ${options.passwordHistoryCount} used passwords.`
                    );
                  }
                }
              }

              // 🔐 Security Enhancement: Rate limiting check
              if (security.rateLimit?.enabled) {
                const isBlocked = eventTracker.checkAlert(
                  "password_change_attempt",
                  user.id,
                  {
                    threshold: security.rateLimit.maxAttempts,
                    timeWindow: `${
                      security.rateLimit.windowMs / (1000 * 60)
                    } minutes`,
                    action: "block",
                  }
                );

                if (isBlocked) {
                  throw new Error(
                    "Too many password change attempts. Please try again later."
                  );
                }
              }
            } catch (error) {
              // 🔐 Security Enhancement: Secure error handling
              logger.error("Password validation error", {
                userId: user.id,
                error: error instanceof Error ? error.message : "Unknown error",
                timestamp: new Date().toISOString(),
              });

              // Re-throw with secure message if it's our validation error
              if (
                error instanceof Error &&
                error.message.includes("cannot be one of the last")
              ) {
                throw error;
              }

              // Generic error for other cases
              throw new Error("Password does not meet security requirements");
            }
          },
        },
      ],
      after: [
        {
          matcher: (ctx) =>
            (ctx as any).path === "/auth/login" ||
            (ctx as any).path === "/auth/register",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, adapter, request } = ctx;
            if (user) {
              try {
                // 🔐 Security Enhancement: Track login event
                if (security.auditTrail) {
                  const loginEvent: SecurityEvent = {
                    type:
                      (ctx as any).path === "/auth/login"
                        ? "user_login"
                        : "user_register",
                    userId: user.id,
                    timestamp: new Date().toISOString(),
                    ipAddress:
                      request?.headers?.get?.("x-forwarded-for") ||
                      (request as any)?.ip ||
                      undefined,
                    userAgent:
                      request?.headers?.get?.("user-agent") || undefined,
                  };

                  eventTracker.trackEvent(loginEvent);
                }

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

                    // 🔐 Security Enhancement: Track force password change
                    if (security.metrics?.trackForceChanges) {
                      const forceChangeEvent: SecurityEvent = {
                        type: "force_password_change_triggered",
                        userId: user.id,
                        timestamp: new Date().toISOString(),
                        metadata: { reason: "password_expired" },
                      };

                      eventTracker.trackEvent(forceChangeEvent);
                    }

                    logger.info("Force password change triggered", {
                      userId: user.id,
                      reason: "password_expired",
                      timestamp: new Date().toISOString(),
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

                  // 🔐 Security Enhancement: Track first-time force change
                  if (security.metrics?.trackForceChanges) {
                    const forceChangeEvent: SecurityEvent = {
                      type: "force_password_change_triggered",
                      userId: user.id,
                      timestamp: new Date().toISOString(),
                      metadata: { reason: "first_login" },
                    };

                    eventTracker.trackEvent(forceChangeEvent);
                  }

                  logger.info("Force password change triggered", {
                    userId: user.id,
                    reason: "first_login",
                    timestamp: new Date().toISOString(),
                  });
                }
              } catch (error) {
                // 🔐 Security Enhancement: Secure error handling for metadata operations
                logger.error("User metadata update error", {
                  userId: user.id,
                  error:
                    error instanceof Error ? error.message : "Unknown error",
                  timestamp: new Date().toISOString(),
                });

                // Don't throw here to avoid breaking the login/register flow
                // The core authentication should succeed even if metadata updates fail
              }
            }
          },
        },
        {
          matcher: (ctx) => (ctx as any).path === "/auth/change-password",
          handler: async (ctx) => {
            // @ts-ignore
            const { user, adapter, input, request } = ctx;
            const password = input?.password;
            if (user && password) {
              try {
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

                // 🔐 Security Enhancement: Data retention policy enforcement
                const retentionCount =
                  security.dataRetention?.passwordHistory?.retainCount ||
                  options.passwordHistoryCount;

                // Manter apenas o número necessário de entradas no histórico
                const allHistory = await adapter.findMany({
                  model: "pciPasswordHistory",
                  where: [{ field: "userId", value: user.id }],
                  orderBy: [{ field: "createdAt", direction: "desc" }],
                });

                if (allHistory.length > retentionCount) {
                  const toDelete = allHistory.slice(retentionCount);
                  for (const entry of toDelete) {
                    await adapter.delete({
                      model: "pciPasswordHistory",
                      where: [{ field: "id", value: entry.id }],
                    });
                  }

                  // 🔐 Security Enhancement: Log cleanup action
                  logger.info("Password history cleanup performed", {
                    userId: user.id,
                    deletedCount: toDelete.length,
                    retainedCount: retentionCount,
                    timestamp: new Date().toISOString(),
                  });
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

                // 🔐 Security Enhancement: Track successful password change
                if (security.auditTrail) {
                  const changeEvent: SecurityEvent = {
                    type: "password_change_success",
                    userId: user.id,
                    timestamp: new Date().toISOString(),
                    ipAddress:
                      request?.headers?.get?.("x-forwarded-for") ||
                      (request as any)?.ip ||
                      undefined,
                    userAgent:
                      request?.headers?.get?.("user-agent") || undefined,
                  };

                  eventTracker.trackEvent(changeEvent);
                }

                logger.info("Password change successful", {
                  userId: user.id,
                  timestamp: new Date().toISOString(),
                });
              } catch (error) {
                // 🔐 Security Enhancement: Secure error handling
                logger.error("Password change operation failed", {
                  userId: user.id,
                  error:
                    error instanceof Error ? error.message : "Unknown error",
                  timestamp: new Date().toISOString(),
                });

                throw new Error("Failed to update password. Please try again.");
              }
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
      // 🔐 Security Enhancement: Optional audit log table
      ...(security.auditTrail && {
        pciAuditLog: {
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
            eventType: { type: "string", required: true },
            // @ts-ignore
            timestamp: { type: "date", required: true },
            // @ts-ignore
            ipAddress: { type: "string", default: null },
            // @ts-ignore
            userAgent: { type: "string", default: null },
            // @ts-ignore
            metadata: { type: "string", default: null }, // JSON string
          },
        },
      }),
    },
  };
}


