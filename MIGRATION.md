# Migration Guide 🔄

Complete guide for integrating the Better Auth PCI DSS Plugin into your project.

## 📋 **Plugin Features**

- **🔐 Security Architecture**: Dedicated tables isolate sensitive data from API exposure
- **📊 Advanced Monitoring**: Security event tracking, alerting, and audit trails
- **🛡️ Enterprise Features**: Rate limiting, data retention, compliance reporting
- **⚡ Performance**: Optimized queries and proper database indexing
- **🔧 Flexible Config**: Optional security features for incremental adoption

---

## 🚀 **Fresh Installation**

### **1. Install**
```bash
npm install better-auth-pci-dss-plugin bcrypt
npm install --save-dev @types/bcrypt
```

### **2. Basic Configuration**
```typescript
import { betterAuth } from 'better-auth';
import { pciDssPasswordPolicy } from 'better-auth-pci-dss-plugin';

export const auth = betterAuth({
  database: {
    provider: "postgresql",
    url: process.env.DATABASE_URL,
  },
  plugins: [
    pciDssPasswordPolicy({
      passwordHistoryCount: 4,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 180,
      forcePasswordChangeOnFirstLogin: true,
    }),
  ],
});
```

### **3. Database Tables**
Plugin automatically creates:

```sql
-- Password history (ultra-sensitive data)
CREATE TABLE "pciPasswordHistory" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "passwordHash" VARCHAR(255) NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- User metadata (operational data)
CREATE TABLE "pciUserMetadata" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID UNIQUE NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "lastPasswordChange" TIMESTAMP WITH TIME ZONE,
  "forcePasswordChange" BOOLEAN DEFAULT false,
  "lastLoginDate" TIMESTAMP WITH TIME ZONE,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Audit log (optional - when auditTrail: true)
CREATE TABLE "pciAuditLog" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "eventType" VARCHAR(100) NOT NULL,
  "timestamp" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "ipAddress" VARCHAR(45),
  "userAgent" TEXT,
  "metadata" TEXT
);
```

### **4. Performance Indexes**
```sql
-- Essential indexes for performance
CREATE INDEX "idx_pci_password_history_user_created" 
ON "pciPasswordHistory"("userId", "createdAt" DESC);

CREATE INDEX "idx_pci_user_metadata_user" 
ON "pciUserMetadata"("userId");

CREATE INDEX "idx_pci_password_history_created" 
ON "pciPasswordHistory"("createdAt");

-- Audit log indexes (if enabled)
CREATE INDEX "idx_pci_audit_log_user_timestamp" 
ON "pciAuditLog"("userId", "timestamp" DESC);

CREATE INDEX "idx_pci_audit_log_event_timestamp" 
ON "pciAuditLog"("eventType", "timestamp" DESC);
```

---

## 🔄 **Adding to Existing Better Auth Project**

### **Step 1: Backup Database**
```bash
# PostgreSQL
pg_dump your_database > backup_$(date +%Y%m%d_%H%M%S).sql

# MySQL
mysqldump your_database > backup_$(date +%Y%m%d_%H%M%S).sql
```

### **Step 2: Install Plugin**
```bash
npm install better-auth-pci-dss-plugin bcrypt
npm install --save-dev @types/bcrypt
```

### **Step 3: Update Better Auth Configuration**
```typescript
// Before: Basic Better Auth setup
export const auth = betterAuth({
  database: {
    provider: "postgresql",
    url: process.env.DATABASE_URL,
  },
  // ... other config
});

// After: With PCI DSS plugin
export const auth = betterAuth({
  database: {
    provider: "postgresql",
    url: process.env.DATABASE_URL,
  },
  plugins: [
    pciDssPasswordPolicy({
      passwordHistoryCount: 4,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 180,
      forcePasswordChangeOnFirstLogin: true,
    }),
  ],
  // ... other config
});
```

### **Step 4: Database Setup**

**⚠️ CRITICAL**: Run in maintenance window with database backup.

```sql
-- Plugin will automatically create these tables on first run
-- But you can create them manually for controlled deployment:

CREATE TABLE "pciPasswordHistory" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "passwordHash" VARCHAR(255) NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE "pciUserMetadata" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID UNIQUE NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "lastPasswordChange" TIMESTAMP WITH TIME ZONE,
  "forcePasswordChange" BOOLEAN DEFAULT false,
  "lastLoginDate" TIMESTAMP WITH TIME ZONE,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create performance indexes
CREATE INDEX "idx_pci_password_history_user_created" 
ON "pciPasswordHistory"("userId", "createdAt" DESC);

CREATE INDEX "idx_pci_user_metadata_user" 
ON "pciUserMetadata"("userId");

-- Initialize metadata for existing users (optional)
INSERT INTO "pciUserMetadata" ("userId", "createdAt", "updatedAt")
SELECT id, NOW(), NOW() FROM "user"
ON CONFLICT ("userId") DO NOTHING;
```

### **Step 5: Test Migration**
```typescript
// Test password change functionality
try {
  await auth.changePassword({
    currentPassword: 'current123',
    newPassword: 'new456',
  });
  console.log('✅ Password change working');
} catch (error) {
  console.error('❌ Password change failed:', error.message);
}

// Test history validation
try {
  await auth.changePassword({
    currentPassword: 'new456',
    newPassword: 'current123', // Should fail - reusing password
  });
  console.error('❌ History validation not working');
} catch (error) {
  console.log('✅ History validation working:', error.message);
}
```

---

## 🛡️ **Advanced Security Setup**

### **Gradual Feature Adoption**
```typescript
export const auth = betterAuth({
  plugins: [
    pciDssPasswordPolicy({
      // Core requirements
      passwordHistoryCount: 4,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 180,
      forcePasswordChangeOnFirstLogin: true,
      
      // Add security features incrementally
      security: {
        // Phase 1: Basic logging
        logger: winston.createLogger({
          level: 'info',
          format: winston.format.json(),
          transports: [
            new winston.transports.File({ filename: 'security.log' }),
          ],
        }),
        
        // Phase 2: Add metrics
        metrics: {
          trackPasswordChanges: true,
          trackHistoryViolations: true,
        },
        
        // Phase 3: Add rate limiting
        rateLimit: {
          enabled: true,
          maxAttempts: 3,
          windowMs: 15 * 60 * 1000, // 15 minutes
        },
        
        // Phase 4: Add audit trail
        auditTrail: true,
        
        // Phase 5: Add alerting
        alerts: {
          passwordHistoryViolations: {
            threshold: 3,
            timeWindow: '1 hour',
            callback: async (event) => {
              await sendSecurityAlert('Password History Violation', event);
            },
          },
        },
      },
    }),
  ],
});
```

### **Production Security Monitoring**
```typescript
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'security-events.log' }),
    new winston.transports.Console({ level: 'warn' }),
  ],
});

// Custom security alert handler
async function sendSecurityAlert(type: string, event: any) {
  const alertData = {
    type,
    timestamp: new Date().toISOString(),
    userId: event.userId,
    metadata: event.metadata,
    severity: event.severity || 'medium',
  };
  
  // Send to security team
  await fetch(process.env.SECURITY_WEBHOOK_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(alertData),
  });
}
```

---

## 🚨 **Troubleshooting**

### **Common Migration Issues**

**Issue**: Foreign key constraint errors
```sql
-- Solution: Ensure user table exists and has proper structure
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'user' AND column_name = 'id';
```

**Issue**: Plugin tables not created automatically
```sql
-- Solution: Check Better Auth database adapter permissions
-- Ensure the database user has CREATE TABLE permissions
GRANT CREATE ON DATABASE your_database TO your_db_user;
```

**Issue**: Performance issues with large user base
```sql
-- Solution: Ensure indexes are created and optimized
\d+ "pciPasswordHistory"  -- Check if indexes exist
ANALYZE "pciPasswordHistory"; -- Update table statistics
```

### **Rollback Procedure**
```sql
-- Emergency rollback (if needed)
BEGIN;

-- Drop plugin tables (ONLY if rollback is necessary)
DROP TABLE IF EXISTS "pciAuditLog";
DROP TABLE IF EXISTS "pciPasswordHistory";
DROP TABLE IF EXISTS "pciUserMetadata";

COMMIT;

-- Remove plugin from Better Auth configuration
-- Restart application
```

---

## 🔄 **Different Database Providers**

### **PostgreSQL**
```typescript
// Already shown above - default configuration
```

### **MySQL**
```sql
-- MySQL equivalent tables
CREATE TABLE `pciPasswordHistory` (
  `id` VARCHAR(36) PRIMARY KEY DEFAULT (UUID()),
  `userId` VARCHAR(36) NOT NULL,
  `passwordHash` VARCHAR(255) NOT NULL,
  `createdAt` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`userId`) REFERENCES `user`(`id`) ON DELETE CASCADE
);

CREATE INDEX `idx_pci_password_history_user_created` 
ON `pciPasswordHistory`(`userId`, `createdAt` DESC);
```

### **SQLite**
```sql
-- SQLite equivalent tables
CREATE TABLE "pciPasswordHistory" (
  "id" TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  "userId" TEXT NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "passwordHash" TEXT NOT NULL,
  "createdAt" DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "idx_pci_password_history_user_created" 
ON "pciPasswordHistory"("userId", "createdAt" DESC);
```

---

## ✅ **Post-Migration Checklist**

- [ ] Database backup completed successfully
- [ ] Plugin tables created with proper constraints
- [ ] Performance indexes created
- [ ] Application tests passing
- [ ] Security features configured appropriately
- [ ] Monitoring and alerting active (if enabled)
- [ ] Documentation updated for team
- [ ] Production deployment tested in staging

---

## 📞 **Support**

**Migration Issues**: Open GitHub issue with:
- Better Auth version
- Database provider and version
- Plugin configuration
- Complete error message
- Relevant database schema

**Security Questions**: Review [SECURITY.md](./SECURITY.md) first, then contact security team.

---

> **⚠️ Critical**: Always test migration in staging environment first. Keep database backups. Plan maintenance window for production deployment. 