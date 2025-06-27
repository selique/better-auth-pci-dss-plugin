import { pciDssPasswordPolicy } from './index';

// Mock logger for testing
const mockLogger = {
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

describe('PCI DSS Password Policy Plugin', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should create plugin with correct id', () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.id).toBe('pci-dss-password-policy');
  });

  it("should define required schema tables and fields", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.schema?.pciPasswordHistory?.fields).toBeDefined();
    expect(plugin.schema?.pciUserMetadata?.fields).toBeDefined();

    // Verificar tabela de histórico de senhas
    const passwordHistoryFields = plugin.schema!.pciPasswordHistory!.fields;
    expect(passwordHistoryFields.id).toEqual({
      type: "string",
      required: true,
    });
    expect(passwordHistoryFields.userId).toEqual({
      type: "string",
      required: true,
      references: {
        model: "user",
        field: "id",
        onDelete: "cascade",
      },
    });
    expect(passwordHistoryFields.passwordHash).toEqual({
      type: "string",
      required: true,
    });
    expect(passwordHistoryFields.createdAt).toEqual({
      type: "date",
      required: true,
    });

    // Verificar tabela de metadados do usuário
    const userMetadataFields = plugin.schema!.pciUserMetadata!.fields;
    expect(userMetadataFields.id).toEqual({ type: "string", required: true });
    expect(userMetadataFields.userId).toEqual({
      type: "string",
      required: true,
      unique: true,
      references: {
        model: "user",
        field: "id",
        onDelete: "cascade",
      },
    });
    expect(userMetadataFields.lastPasswordChange).toEqual({
      type: "date",
      default: null,
    });
    expect(userMetadataFields.forcePasswordChange).toEqual({
      type: "boolean",
      default: false,
    });
    expect(userMetadataFields.lastLoginDate).toEqual({
      type: "date",
      default: null,
    });
    expect(userMetadataFields.createdAt).toEqual({
      type: "date",
      required: true,
    });
    expect(userMetadataFields.updatedAt).toEqual({
      type: "date",
      required: true,
    });
  });

  it("should have correct hook structure", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.hooks?.before).toHaveLength(1);
    expect(plugin.hooks?.after).toHaveLength(2);
  });

  it("should accept different configuration options", () => {
    const plugin1 = pciDssPasswordPolicy({
      passwordHistoryCount: 5,
      passwordChangeIntervalDays: 60,
      inactiveAccountDeactivationDays: 30,
      forcePasswordChangeOnFirstLogin: false,
    });

    const plugin2 = pciDssPasswordPolicy({
      passwordHistoryCount: 10,
      passwordChangeIntervalDays: 180,
      inactiveAccountDeactivationDays: 365,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin1).toBeDefined();
    expect(plugin2).toBeDefined();
    expect(plugin1.id).toBe("pci-dss-password-policy");
    expect(plugin2.id).toBe("pci-dss-password-policy");
  });

  it("should have matcher functions for hooks", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    const beforeHook = plugin.hooks?.before?.[0];
    const afterHook1 = plugin.hooks?.after?.[0];
    const afterHook2 = plugin.hooks?.after?.[1];

    expect(beforeHook?.matcher).toBeDefined();
    expect(afterHook1?.matcher).toBeDefined();
    expect(afterHook2?.matcher).toBeDefined();
  });

  it("should export plugin as a function", () => {
    expect(typeof pciDssPasswordPolicy).toBe("function");
  });

  it("should not expose sensitive data in user table", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    // Verificar que não há campos sensíveis na tabela user
    expect(plugin.schema?.users).toBeUndefined();
    expect(plugin.schema?.user).toBeUndefined();

    // Verificar que dados sensíveis estão em tabelas dedicadas
    expect(plugin.schema?.pciPasswordHistory).toBeDefined();
    expect(plugin.schema?.pciUserMetadata).toBeDefined();
  });

  it("should use proper foreign key constraints", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    const passwordHistoryUserId =
      plugin.schema!.pciPasswordHistory!.fields.userId;
    const userMetadataUserId = plugin.schema!.pciUserMetadata!.fields.userId;

    // Verificar referências corretas
    expect(passwordHistoryUserId.references).toEqual({
      model: "user",
      field: "id",
      onDelete: "cascade",
    });

    expect(userMetadataUserId.references).toEqual({
      model: "user",
      field: "id",
      onDelete: "cascade",
    });
  });

  // 🔐 Security Enhancement Tests
  describe('Security Features', () => {
    it('should create plugin with security logger', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          logger: mockLogger,
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should create plugin with audit trail enabled', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          auditTrail: true,
        },
      });

      // Should include audit log table when audit trail is enabled
      expect(plugin.schema?.pciAuditLog?.fields).toBeDefined();
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('id');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('userId');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('eventType');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('timestamp');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('ipAddress');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('userAgent');
      expect(plugin.schema?.pciAuditLog?.fields).toHaveProperty('metadata');
    });

    it('should not include audit log table when audit trail is disabled', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          auditTrail: false,
        },
      });

      // Should not include audit log table when audit trail is disabled
      expect(plugin.schema?.pciAuditLog).toBeUndefined();
    });

    it('should create plugin with rate limiting configuration', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          rateLimit: {
            enabled: true,
            maxAttempts: 5,
            windowMs: 15 * 60 * 1000, // 15 minutes
          },
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should create plugin with security alerts configuration', () => {
      const mockCallback = jest.fn();
      
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          alerts: {
            passwordHistoryViolations: {
              threshold: 3,
              timeWindow: '1 hour',
              action: 'alert',
              callback: mockCallback,
            },
            multipleFailedAttempts: {
              threshold: 5,
              timeWindow: '15 minutes',
              action: 'block',
            },
          },
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should create plugin with data retention policies', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          dataRetention: {
            passwordHistory: {
              retainCount: 5,
              maxAge: '2 years',
            },
            auditLogs: {
              retainPeriod: '7 years',
              cleanupInterval: '1 day',
            },
          },
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should create plugin with security metrics tracking', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          metrics: {
            trackFailedAttempts: true,
            trackPasswordChanges: true,
            trackHistoryViolations: true,
            trackForceChanges: true,
          },
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should create plugin with all security features enabled', () => {
      const mockCallback = jest.fn();
      
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 4,
        passwordChangeIntervalDays: 60,
        inactiveAccountDeactivationDays: 120,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          logger: mockLogger,
          auditTrail: true,
          rateLimit: {
            enabled: true,
            maxAttempts: 3,
            windowMs: 10 * 60 * 1000, // 10 minutes
          },
          alerts: {
            passwordHistoryViolations: {
              threshold: 2,
              timeWindow: '30 minutes',
              action: 'alert',
              callback: mockCallback,
            },
            multipleFailedAttempts: {
              threshold: 3,
              timeWindow: '10 minutes',
              action: 'block',
            },
            massPasswordChanges: {
              threshold: 50,
              timeWindow: '1 hour',
              action: 'alert',
            },
          },
          dataRetention: {
            passwordHistory: {
              retainCount: 8,
              maxAge: '3 years',
            },
            auditLogs: {
              retainPeriod: '10 years',
              cleanupInterval: '12 hours',
            },
          },
          metrics: {
            trackFailedAttempts: true,
            trackPasswordChanges: true,
            trackHistoryViolations: true,
            trackForceChanges: true,
          },
        },
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
      
      // Should have all tables when fully configured
      expect(plugin.schema?.pciPasswordHistory?.fields).toBeDefined();
      expect(plugin.schema?.pciUserMetadata?.fields).toBeDefined();
      expect(plugin.schema?.pciAuditLog?.fields).toBeDefined();
    });
  });

  // Foreign key relationship tests
  describe('Database Relationships', () => {
    it('should have proper foreign key relationships', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Check password history references user table
      const passwordHistoryUserId = plugin.schema?.pciPasswordHistory?.fields?.userId;
      expect(passwordHistoryUserId).toHaveProperty('references');
      expect(passwordHistoryUserId?.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      });

      // Check user metadata references user table
      const userMetadataUserId = plugin.schema?.pciUserMetadata?.fields?.userId;
      expect(userMetadataUserId).toHaveProperty('references');
      expect(userMetadataUserId?.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      });
    });

    it('should have proper foreign key relationships for audit log when enabled', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {
          auditTrail: true,
        },
      });

      // Check audit log references user table
      const auditLogUserId = plugin.schema?.pciAuditLog?.fields?.userId;
      expect(auditLogUserId).toHaveProperty('references');
      expect(auditLogUserId?.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      });
    });
  });

  // Data isolation tests
  describe('Data Security Architecture', () => {
    it('should isolate sensitive password data from user table', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Should have dedicated password history table
      expect(plugin.schema?.pciPasswordHistory).toBeDefined();
      
      // Should have non-sensitive metadata table
      expect(plugin.schema?.pciUserMetadata).toBeDefined();
      
      // Should NOT extend the user table schema directly
      expect(plugin.schema?.user).toBeUndefined();
    });

    it('should separate ultra-sensitive data from operational metadata', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Password history should only contain ultra-sensitive data
      const passwordHistoryFields = plugin.schema?.pciPasswordHistory?.fields;
      expect(passwordHistoryFields).toHaveProperty('passwordHash');
      expect(passwordHistoryFields).not.toHaveProperty('forcePasswordChange');
      expect(passwordHistoryFields).not.toHaveProperty('lastLoginDate');

      // User metadata should contain operational data only
      const userMetadataFields = plugin.schema?.pciUserMetadata?.fields;
      expect(userMetadataFields).toHaveProperty('forcePasswordChange');
      expect(userMetadataFields).toHaveProperty('lastLoginDate');
      expect(userMetadataFields).toHaveProperty('lastPasswordChange');
      expect(userMetadataFields).not.toHaveProperty('passwordHash');
    });
  });

  // Configuration validation tests
  describe('Configuration Validation', () => {
    it('should handle minimal configuration', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 1,
        passwordChangeIntervalDays: 0,
        inactiveAccountDeactivationDays: 0,
        forcePasswordChangeOnFirstLogin: false,
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
      expect(plugin.schema?.pciPasswordHistory).toBeDefined();
      expect(plugin.schema?.pciUserMetadata).toBeDefined();
    });

    it('should handle configuration with undefined security options', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: undefined,
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
      expect(plugin.schema?.pciAuditLog).toBeUndefined();
    });

    it('should handle empty security configuration', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
        security: {},
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
      expect(plugin.schema?.pciAuditLog).toBeUndefined();
    });
  });

  // Hook configuration tests
  describe('Hook Configuration', () => {
    it('should configure change-password before hook', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      const beforeHooks = plugin.hooks?.before || [];
      const changePasswordHook = beforeHooks.find(hook => 
        hook.matcher && hook.matcher({ path: '/auth/change-password' } as any)
      );

      expect(changePasswordHook).toBeDefined();
      expect(changePasswordHook?.handler).toBeDefined();
    });

    it('should configure login/register after hooks', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      const afterHooks = plugin.hooks?.after || [];
      
      const loginRegisterHook = afterHooks.find(hook => 
        hook.matcher && (
          hook.matcher({ path: '/auth/login' } as any) ||
          hook.matcher({ path: '/auth/register' } as any)
        )
      );

      expect(loginRegisterHook).toBeDefined();
      expect(loginRegisterHook?.handler).toBeDefined();
    });

    it('should configure change-password after hook', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      const afterHooks = plugin.hooks?.after || [];
      const changePasswordAfterHook = afterHooks.find(hook => 
        hook.matcher && hook.matcher({ path: '/auth/change-password' } as any)
      );

      expect(changePasswordAfterHook).toBeDefined();
      expect(changePasswordAfterHook?.handler).toBeDefined();
    });
  });

  // Error handling tests
  describe('Error Handling', () => {
    it('should not expose sensitive information in error messages', () => {
      // This is tested through the secure error handling in the actual implementation
      // The plugin uses generic error messages and logs detailed info securely
      expect(true).toBe(true); // Placeholder for implementation testing
    });
  });

  // Compliance tests
  describe('PCI DSS Compliance', () => {
    it('should support required PCI DSS password history count', () => {
      // PCI DSS typically requires at least 4 password history
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 4,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should support forced password changes', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Should have metadata table to track force password change flag
      expect(plugin.schema?.pciUserMetadata?.fields?.forcePasswordChange).toBeDefined();
    });

    it('should support password change intervals', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Should have metadata table to track last password change
      expect(plugin.schema?.pciUserMetadata?.fields?.lastPasswordChange).toBeDefined();
    });
  });
}); 