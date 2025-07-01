import { BetterAuthPlugin } from 'better-auth';

export interface SecurityLogger {
  info: (message: string, meta?: any) => void;
  warn: (message: string, meta?: any) => void;
  error: (message: string, meta?: any) => void;
}

export interface SecurityAlert {
  threshold: number;
  timeWindow: string; // e.g., '15 minutes', '1 hour'
  action: "log" | "alert" | "block";
  callback?: (event: SecurityEvent) => void;
}

export interface SecurityEvent {
  type: string;
  userId: string;
  timestamp: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
}

export interface DataRetentionPolicy {
  passwordHistory?: {
    retainCount: number;
    maxAge?: string; // e.g., '2 years'
  };
  auditLogs?: {
    retainPeriod: string;
    cleanupInterval?: string;
  };
}

export interface SecurityMetrics {
  trackFailedAttempts?: boolean;
  trackPasswordChanges?: boolean;
  trackHistoryViolations?: boolean;
  trackForceChanges?: boolean;
}

export interface PCIDSSPasswordPolicyOptions {
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

/**
 * Better Auth PCI DSS Plugin
 * 
 * Provides enterprise-grade password policies and security features
 * compliant with PCI DSS 4.0 requirements.
 * 
 * Features:
 * - Password history enforcement (prevents reuse)
 * - Automatic password expiration
 * - Force password change (first login, expired passwords)  
 * - Zero API exposure (sensitive data isolation)
 * - Comprehensive audit trail
 * - Rate limiting and security alerts
 * - PBKDF2-SHA512 native crypto (better-auth compatible)
 * 
 * @param options Configuration options for the PCI DSS plugin
 * @returns BetterAuthPlugin instance
 */
export declare function pciDssPasswordPolicy(
  options: PCIDSSPasswordPolicyOptions
): BetterAuthPlugin; 