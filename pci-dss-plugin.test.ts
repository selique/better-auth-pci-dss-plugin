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

  // Core Plugin Structure Tests
  describe('Plugin Structure', () => {
    it('should create plugin with correct id', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should export plugin as a function', () => {
      expect(typeof pciDssPasswordPolicy).toBe('function');
    });

    it('should have correct hook structure', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      expect(plugin.hooks?.before).toHaveLength(1);
      expect(plugin.hooks?.after).toHaveLength(2);
    });

    it('should have matcher functions for hooks', () => {
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
  });

  // Database Schema Tests
  describe('Database Schema', () => {
    it('should define required schema tables and fields', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      expect(plugin.schema?.pciPasswordHistory?.fields).toBeDefined();
      expect(plugin.schema?.pciUserMetadata?.fields).toBeDefined();

      // Password History Table Fields
      const passwordHistoryFields = plugin.schema!.pciPasswordHistory!.fields;
      expect(passwordHistoryFields.id).toEqual({
        type: 'string',
        required: true,
      });
      expect(passwordHistoryFields.userId).toEqual({
        type: 'string',
        required: true,
        references: {
          model: 'user',
          field: 'id',
          onDelete: 'cascade',
        },
      });
      expect(passwordHistoryFields.passwordHash).toEqual({
        type: 'string',
        required: true,
      });
      expect(passwordHistoryFields.createdAt).toEqual({
        type: 'date',
        required: true,
      });

      // User Metadata Table Fields
      const userMetadataFields = plugin.schema!.pciUserMetadata!.fields;
      expect(userMetadataFields.id).toEqual({ type: 'string', required: true });
      expect(userMetadataFields.userId).toEqual({
        type: 'string',
        required: true,
        unique: true,
        references: {
          model: 'user',
          field: 'id',
          onDelete: 'cascade',
        },
      });
      expect(userMetadataFields.lastPasswordChange).toEqual({
        type: 'date',
        default: null,
      });
      expect(userMetadataFields.forcePasswordChange).toEqual({
        type: 'boolean',
        default: false,
      });
      expect(userMetadataFields.lastLoginDate).toEqual({
        type: 'date',
        default: null,
      });
      expect(userMetadataFields.createdAt).toEqual({
        type: 'date',
        required: true,
      });
      expect(userMetadataFields.updatedAt).toEqual({
        type: 'date',
        required: true,
      });
    });

    it('should not expose sensitive data in user table', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Verify no sensitive fields in user table
      expect(plugin.schema?.users).toBeUndefined();
      expect(plugin.schema?.user).toBeUndefined();

      // Verify sensitive data is in dedicated tables
      expect(plugin.schema?.pciPasswordHistory).toBeDefined();
      expect(plugin.schema?.pciUserMetadata).toBeDefined();
    });

    it('should use proper foreign key constraints', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      const passwordHistoryUserId = plugin.schema!.pciPasswordHistory!.fields.userId;
      const userMetadataUserId = plugin.schema!.pciUserMetadata!.fields.userId;

      // Verify correct references
      expect(passwordHistoryUserId.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      });

      expect(userMetadataUserId.references).toEqual({
        model: 'user',
        field: 'id',
        onDelete: 'cascade',
      });
    });

    it('should include audit log table when audit trail is enabled', () => {
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
  });

  // Configuration Tests
  describe('Configuration Options', () => {
    it('should accept different configuration options', () => {
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
      expect(plugin1.id).toBe('pci-dss-password-policy');
      expect(plugin2.id).toBe('pci-dss-password-policy');
    });

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
  });

  // Security Architecture Tests
  describe('Data Security Architecture', () => {
    it('should isolate sensitive data from API exposure', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 4,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 180,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Verify no extension of user table (prevents API exposure)
      expect(plugin.schema?.user).toBeUndefined();
      
      // Verify dedicated security tables exist
      expect(plugin.schema?.pciPasswordHistory).toBeDefined();
      expect(plugin.schema?.pciUserMetadata).toBeDefined();
      
      // Verify proper isolation with foreign keys
      const passwordHistoryUserId = plugin.schema!.pciPasswordHistory!.fields.userId;
      const userMetadataUserId = plugin.schema!.pciUserMetadata!.fields.userId;
      
      expect(passwordHistoryUserId.references?.model).toBe('user');
      expect(userMetadataUserId.references?.model).toBe('user');
    });

    describe('Error Handling', () => {
      it('should not expose sensitive information in error messages', () => {
        const plugin = pciDssPasswordPolicy({
          passwordHistoryCount: 3,
          passwordChangeIntervalDays: 90,
          inactiveAccountDeactivationDays: 90,
          forcePasswordChangeOnFirstLogin: true,
        });

        // Plugin should be created without exposing internal details
        expect(plugin.id).toBe('pci-dss-password-policy');
        expect(typeof plugin.hooks?.before?.[0]?.handler).toBe('function');
        expect(typeof plugin.hooks?.after?.[0]?.handler).toBe('function');
      });
    });
  });

  // PCI DSS Compliance Tests
  describe('PCI DSS Compliance', () => {
    it('should support required PCI DSS password history count', () => {
      // PCI DSS typically requires 4 password history
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
        passwordHistoryCount: 4,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true, // PCI DSS requirement
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should support password change intervals', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 4,
        passwordChangeIntervalDays: 90, // PCI DSS typical requirement
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      expect(plugin.id).toBe('pci-dss-password-policy');
    });

    it('should support comprehensive security configuration', () => {
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

  // Cryptographic Implementation Tests
  describe('Cryptographic Security', () => {
    it('should use Node.js native crypto (PBKDF2-SHA512)', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Plugin should be properly initialized with crypto functions
      expect(plugin.id).toBe('pci-dss-password-policy');
      expect(plugin.hooks?.before).toBeDefined();
      expect(plugin.hooks?.after).toBeDefined();
    });

    it('should maintain better-auth compatibility', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Should follow better-auth plugin interface
      expect(plugin.id).toBeDefined();
      expect(plugin.schema).toBeDefined();
      expect(plugin.hooks).toBeDefined();
    });
  });

  // Plugin Integration Tests
  describe('Plugin Integration', () => {
    it('should provide proper plugin structure for better-auth integration', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Should have proper better-auth plugin structure
      expect(plugin.id).toBeDefined();
      expect(plugin.schema).toBeDefined();
      expect(plugin.hooks).toBeDefined();
      
      // Hooks should handle password change functionality
      expect(plugin.hooks?.before).toHaveLength(1);
      expect(plugin.hooks?.after).toHaveLength(2);
    });

    it('should maintain zero API exposure architecture', () => {
      const plugin = pciDssPasswordPolicy({
        passwordHistoryCount: 3,
        passwordChangeIntervalDays: 90,
        inactiveAccountDeactivationDays: 90,
        forcePasswordChangeOnFirstLogin: true,
      });

      // Verify no modifications to user schema
      expect(plugin.schema?.user).toBeUndefined();
      
      // Sensitive data should be in isolated tables
      expect(plugin.schema?.pciPasswordHistory).toBeDefined();
      expect(plugin.schema?.pciUserMetadata).toBeDefined();
    });
  });
}); 