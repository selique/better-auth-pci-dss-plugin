# Migration Guide 🔄

This guide helps you migrate to the latest version of the Better Auth PCI DSS Plugin or implement it for the first time.

## 📋 **Migration Overview**

### **What's New in v2.0**
- **🔐 Enhanced Security Architecture**: Dedicated tables for sensitive data isolation
- **📊 Advanced Monitoring**: Security event tracking and alerting
- **🛡️ Production Features**: Rate limiting, audit trails, data retention policies
- **⚡ Performance Optimizations**: Improved database queries and indexing
- **🔧 Flexible Configuration**: Optional security features you can enable incrementally

### **Breaking Changes**
- **Database Schema**: New dedicated tables replace user table extensions
- **Configuration**: New optional `security` configuration object
- **Dependencies**: Requires bcrypt for password hashing

---

## 🚀 **Fresh Installation**

### **1. Install the Plugin**
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
    provider: "postgresql", // or your database provider
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

### **3. Database Migration**
The plugin will automatically create these tables:

```sql
-- 🔐 Password history (ultra-sensitive data)
CREATE TABLE "pciPasswordHistory" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "passwordHash" VARCHAR(255) NOT NULL,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 📋 User metadata (operational data)
CREATE TABLE "pciUserMetadata" (
  "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  "userId" UUID UNIQUE NOT NULL REFERENCES "user"("id") ON DELETE CASCADE,
  "lastPasswordChange" TIMESTAMP WITH TIME ZONE,
  "forcePasswordChange" BOOLEAN DEFAULT false,
  "lastLoginDate" TIMESTAMP WITH TIME ZONE,
  "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- 📝 Audit log (optional - when auditTrail: true)
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

### **4. Recommended Indexes**
```sql
-- Performance optimization indexes
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

## 🔄 **Migrating from v1.x**

### **Step 1: Backup Your Database**
```bash
# PostgreSQL
pg_dump your_database > backup_$(date +%Y%m%d_%H%M%S).sql

# MySQL
mysqldump your_database > backup_$(date +%Y%m%d_%H%M%S).sql
```

### **Step 2: Update Dependencies**
```bash
npm install better-auth-pci-dss-plugin@latest bcrypt
npm install --save-dev @types/bcrypt
```

### **Step 3: Update Configuration**
```typescript
// OLD v1.x configuration
const plugin = pciDssPasswordPolicy({
  passwordHistoryCount: 4,
  passwordChangeIntervalDays: 90,
  inactiveAccountDeactivationDays: 180,
  forcePasswordChangeOnFirstLogin: true,
});

// NEW v2.x configuration (backward compatible)
const plugin = pciDssPasswordPolicy({
  passwordHistoryCount: 4,
  passwordChangeIntervalDays: 90,
  inactiveAccountDeactivationDays: 180,
  forcePasswordChangeOnFirstLogin: true,
  
  // Optional: Add security features incrementally
  security: {
    // Start with basic logging
    logger: console, // or your preferred logger
    
    // Enable as needed
    auditTrail: false,
    metrics: {
      trackPasswordChanges: true,
    },
  },
});
```

### **Step 4: Database Migration Script**

**⚠️ IMPORTANT**: Run this migration script carefully in a maintenance window.

```sql
-- Step 4a: Create new tables
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

-- Step 4b: Migrate existing data (if you had v1.x data in user table)
-- WARNING: Adjust column names based on your v1.x implementation

-- Migrate password history (if stored as array in user table)
DO $$
DECLARE
  user_record RECORD;
  history_entry TEXT;
BEGIN
  FOR user_record IN 
    SELECT id, "passwordHistory", "lastPasswordChange", "forcePasswordChange", "lastLoginDate"
    FROM "user" 
    WHERE "passwordHistory" IS NOT NULL
  LOOP
    -- Migrate password history entries
    IF user_record."passwordHistory" IS NOT NULL THEN
      FOREACH history_entry IN ARRAY user_record."passwordHistory"
      LOOP
        INSERT INTO "pciPasswordHistory" ("userId", "passwordHash", "createdAt")
        VALUES (
          user_record.id, 
          history_entry, 
          COALESCE(user_record."lastPasswordChange", NOW())
        );
      END LOOP;
    END IF;
    
    -- Migrate user metadata
    INSERT INTO "pciUserMetadata" (
      "userId", 
      "lastPasswordChange", 
      "forcePasswordChange", 
      "lastLoginDate",
      "createdAt",
      "updatedAt"
    ) VALUES (
      user_record.id,
      user_record."lastPasswordChange",
      COALESCE(user_record."forcePasswordChange", false),
      user_record."lastLoginDate",
      NOW(),
      NOW()
    ) ON CONFLICT ("userId") DO NOTHING;
  END LOOP;
END $$;

-- Step 4c: Clean up old columns (ONLY after verifying migration worked)
-- UNCOMMENT THESE LINES AFTER TESTING:
-- ALTER TABLE "user" DROP COLUMN IF EXISTS "passwordHistory";
-- ALTER TABLE "user" DROP COLUMN IF EXISTS "lastPasswordChange";
-- ALTER TABLE "user" DROP COLUMN IF EXISTS "forcePasswordChange";
-- ALTER TABLE "user" DROP COLUMN IF EXISTS "lastLoginDate";

-- Step 4d: Add performance indexes
CREATE INDEX "idx_pci_password_history_user_created" 
ON "pciPasswordHistory"("userId", "createdAt" DESC);

CREATE INDEX "idx_pci_user_metadata_user" 
ON "pciUserMetadata"("userId");

CREATE INDEX "idx_pci_password_history_created" 
ON "pciPasswordHistory"("createdAt");
```

### **Step 5: Verification Script**
```sql
-- Verify migration success
SELECT 
  u.id as user_id,
  u.email,
  m.lastPasswordChange,
  m.forcePasswordChange,
  COUNT(h.id) as password_history_count
FROM "user" u
LEFT JOIN "pciUserMetadata" m ON u.id = m."userId"
LEFT JOIN "pciPasswordHistory" h ON u.id = h."userId"
GROUP BY u.id, u.email, m.lastPasswordChange, m.forcePasswordChange
ORDER BY u.email;

-- Check for any orphaned data
SELECT COUNT(*) as orphaned_metadata 
FROM "pciUserMetadata" m 
WHERE NOT EXISTS (SELECT 1 FROM "user" u WHERE u.id = m."userId");

SELECT COUNT(*) as orphaned_history 
FROM "pciPasswordHistory" h 
WHERE NOT EXISTS (SELECT 1 FROM "user" u WHERE u.id = h."userId");
```

---

## 🔐 **Advanced Security Migration**

### **Enabling Security Features Incrementally**

#### **Phase 1: Basic Monitoring**
```typescript
security: {
  logger: winston.createLogger({
    transports: [
      new winston.transports.File({ filename: 'security.log' })
    ]
  }),
  metrics: {
    trackPasswordChanges: true,
    trackHistoryViolations: true,
  },
}
```

#### **Phase 2: Rate Limiting**
```typescript
security: {
  // ... previous config
  rateLimit: {
    enabled: true,
    maxAttempts: 5,
    windowMs: 15 * 60 * 1000, // 15 minutes
  },
}
```

#### **Phase 3: Full Monitoring**
```typescript
security: {
  // ... previous config
  auditTrail: true,
  alerts: {
    passwordHistoryViolations: {
      threshold: 3,
      timeWindow: '1 hour',
      action: 'alert',
      callback: async (event) => {
        await notifySecurityTeam(event);
      },
    },
  },
  dataRetention: {
    passwordHistory: {
      retainCount: 12,
      maxAge: '2 years',
    },
    auditLogs: {
      retainPeriod: '7 years',
      cleanupInterval: '1 day',
    },
  },
}
```

---

## 🛠️ **Frontend Integration Updates**

### **Checking User Security Status**
```typescript
// New API to check user security requirements
async function checkUserSecurityStatus(userId: string) {
  const userMetadata = await db.pciUserMetadata.findUnique({
    where: { userId }
  });
  
  return {
    forcePasswordChange: userMetadata?.forcePasswordChange || false,
    lastPasswordChange: userMetadata?.lastPasswordChange,
    passwordAge: userMetadata?.lastPasswordChange 
      ? Math.floor((Date.now() - new Date(userMetadata.lastPasswordChange).getTime()) / (1000 * 60 * 60 * 24))
      : null,
  };
}

// Frontend usage
const userStatus = await checkUserSecurityStatus(user.id);
if (userStatus.forcePasswordChange) {
  // Redirect to password change page
  router.push('/auth/change-password?required=true');
}
```

### **Password Change Form Updates**
```tsx
// React component example
function PasswordChangeForm() {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    
    try {
      await auth.changePassword({ password });
      // Success - redirect or show success message
    } catch (err) {
      // Handle new error messages
      if (err.message.includes('cannot be one of the last')) {
        setError('Password cannot be one of your recent passwords');
      } else if (err.message.includes('Too many password change attempts')) {
        setError('Too many attempts. Please try again later.');
      } else {
        setError('Password change failed. Please try again.');
      }
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input 
        type="password" 
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="New password"
      />
      {error && <div className="error">{error}</div>}
      <button type="submit">Change Password</button>
    </form>
  );
}
```

---

## 📊 **Monitoring & Alerting Setup**

### **Security Dashboard Integration**
```typescript
// Example metrics collection
export async function getSecurityMetrics(timeRange: '24h' | '7d' | '30d') {
  const startDate = getDateFromRange(timeRange);
  
  const [passwordChanges, violations, auditEvents] = await Promise.all([
    db.pciPasswordHistory.count({
      where: { createdAt: { gte: startDate } }
    }),
    
    db.pciAuditLog.count({
      where: { 
        eventType: 'password_history_violation',
        timestamp: { gte: startDate }
      }
    }),
    
    db.pciAuditLog.groupBy({
      by: ['eventType'],
      where: { timestamp: { gte: startDate } },
      _count: true,
    }),
  ]);
  
  return {
    passwordChanges,
    violations,
    auditEvents,
    alerts: await getActiveAlerts(startDate),
  };
}
```

### **Alert Configuration**
```typescript
// Slack/Teams webhook integration
async function notifySecurityTeam(event: SecurityEvent) {
  const webhook = process.env.SECURITY_WEBHOOK_URL;
  
  await fetch(webhook, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      text: `🚨 Security Alert: ${event.type}`,
      blocks: [
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Security Event:* ${event.type}\n*User ID:* ${event.userId}\n*Timestamp:* ${event.timestamp}`
          }
        }
      ]
    })
  });
}
```

---

## 🧪 **Testing Your Migration**

### **Unit Tests**
```bash
npm test
```

### **Integration Tests**
```typescript
// Test password history enforcement
describe('Password History Migration', () => {
  it('should enforce password history after migration', async () => {
    const userId = 'test-user-id';
    const password = 'newPassword123!';
    
    // Change password first time
    await auth.changePassword({ userId, password });
    
    // Try to use same password again - should fail
    await expect(
      auth.changePassword({ userId, password })
    ).rejects.toThrow('cannot be one of the last');
  });
});
```

### **Manual Testing Checklist**
- [ ] Password history validation works
- [ ] Force password change triggers correctly
- [ ] Security logging captures events
- [ ] Rate limiting blocks excessive attempts
- [ ] Database constraints prevent orphaned data
- [ ] Performance is acceptable with new schema

---

## 🚨 **Rollback Plan**

If you need to rollback the migration:

### **Step 1: Stop Application**
```bash
# Stop your application servers
pm2 stop all  # or your process manager
```

### **Step 2: Restore Database**
```bash
# Restore from backup
psql your_database < backup_YYYYMMDD_HHMMSS.sql
```

### **Step 3: Revert Code**
```bash
# Revert to previous version
npm install better-auth-pci-dss-plugin@1.x.x
git checkout previous-working-commit
```

### **Step 4: Restart Application**
```bash
pm2 start all
```

---

## 📞 **Support & Troubleshooting**

### **Common Issues**

#### **Migration Fails with Foreign Key Errors**
```sql
-- Check for orphaned data before migration
SELECT u.id FROM "user" u 
WHERE NOT EXISTS (SELECT 1 FROM "pciUserMetadata" m WHERE m."userId" = u.id);
```

#### **Performance Issues After Migration**
```sql
-- Ensure indexes are created
\d+ "pciPasswordHistory"  -- Should show indexes
\d+ "pciUserMetadata"     -- Should show indexes

-- Check query performance
EXPLAIN ANALYZE 
SELECT * FROM "pciPasswordHistory" 
WHERE "userId" = 'some-uuid' 
ORDER BY "createdAt" DESC LIMIT 5;
```

#### **Security Events Not Logging**
```typescript
// Verify logger configuration
const testLogger = {
  info: (msg, meta) => console.log('INFO:', msg, meta),
  warn: (msg, meta) => console.warn('WARN:', msg, meta),
  error: (msg, meta) => console.error('ERROR:', msg, meta),
};

// Test with simple logger first
security: { logger: testLogger }
```

### **Getting Help**
- 📖 [Documentation](./README.md)
- 🔒 [Security Guide](./SECURITY.md)
- 🤝 [Contributing](./CONTRIBUTING.md)
- 🐛 [Issues](https://github.com/your-repo/issues)

---

> **⚠️ Important**: Always test migrations in a staging environment first. Keep database backups and have a rollback plan ready before migrating production systems.

> **🔐 Security Note**: The new architecture provides significantly better security by isolating sensitive data from user-facing APIs. The migration is worth the effort for enhanced security posture. 