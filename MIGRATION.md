# Migration Guide 🔄

Complete guide for integrating the Better Auth PCI DSS Plugin into your project.

## 🚨 **BREAKING CHANGE - Version 2.0+**

### **⚡ bcrypt → Node.js Crypto Migration**

**Version 2.0+** replaces bcrypt with Node.js native crypto for better-auth compatibility.

#### **Why This Change?**
- ✅ **Zero Dependencies**: No external crypto libraries needed
- ✅ **Better Integration**: Uses same crypto stack as better-auth core
- ✅ **NIST Compliant**: PBKDF2-SHA512 is FIPS 140-2 approved
- ✅ **Performance**: Optimized for server environments
- ✅ **Security**: Same security level, better ecosystem alignment

#### **Migration Impact**
```typescript
// ❌ OLD (v1.x): bcrypt dependency
npm install better-auth-pci-dss-plugin bcrypt @types/bcrypt

// ✅ NEW (v2.0+): Zero dependencies
npm install better-auth-pci-dss-plugin
```

#### **Password Hash Migration**
**IMPORTANT**: Existing bcrypt hashes are **incompatible** with new PBKDF2 implementation.

**Migration Strategy:**
1. **Upgrade plugin** to v2.0+
2. **Existing users** will need to reset passwords
3. **New passwords** use secure PBKDF2-SHA512 format
4. **Migration is automatic** - no database changes needed

```typescript
// Migration behavior:
// 1. User tries login with old bcrypt hash → fails securely
// 2. User resets password → new PBKDF2 hash created  
// 3. Future logins use new secure hash format

// Hash format change:
// OLD: bcrypt hash (60 chars, $2b$ prefix)
// NEW: "salt:iterations:hash" (PBKDF2-SHA512, better-auth compatible)
```

#### **Production Migration Checklist**
- [ ] **Backup database** before upgrading
- [ ] **Test in staging** first
- [ ] **Notify users** about password reset requirement
- [ ] **Update dependencies** (`npm update better-auth-pci-dss-plugin`)
- [ ] **Monitor logs** for migration issues

---

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
npm install better-auth-pci-dss-plugin
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
npm install better-auth-pci-dss-plugin
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

## 📦 **Database Migration Tools & Better Auth Integration**

This section provides ready-to-use SQL migration scripts and integration guides for Better Auth supported databases and migration tools.

### **🗃️ Available Migration Scripts**

Pre-built migration files for Better Auth supported databases:

- **`V1__Create_PCI_DSS_Tables.sql`** - PostgreSQL (recommended for production)

**Note**: For MongoDB, use the MongoDB adapter - no SQL migration needed.

The PostgreSQL script includes:
- ✅ Complete table creation with constraints
- ✅ Performance-optimized indexes
- ✅ Data initialization for existing users
- ✅ Automated cleanup functions
- ✅ Verification queries

---

### **🔧 Migration Tool Integration**

#### **Better Auth CLI (Recommended)**
```bash
# Generate schema for your database adapter
npx @better-auth/cli generate

# Apply migration (Kysely adapter only)
npx @better-auth/cli migrate
```

#### **FlywayDB**
```properties
# flyway.conf
flyway.url=jdbc:postgresql://localhost:5432/your_database
flyway.user=your_username
flyway.password=your_password
flyway.locations=filesystem:db/migration
```

```bash
# Copy the appropriate SQL file to your migrations folder
cp V1__Create_PCI_DSS_Tables.sql db/migration/
flyway migrate
```

#### **Liquibase**
```xml
<!-- changelog.xml -->
<databaseChangeLog>
  <changeSet id="pci-dss-tables" author="dev">
    <sqlFile path="V1__Create_PCI_DSS_Tables.sql"/>
  </changeSet>
</databaseChangeLog>
```

```bash
liquibase update
```

#### **Prisma Migrations**
```sql
-- prisma/migrations/001_pci_dss_tables/migration.sql
-- Copy the content from V1__Create_PCI_DSS_Tables.sql here
```

```bash
# Generate and apply migration
npx prisma db push
# or
npx prisma migrate dev --name pci-dss-tables
```

#### **Drizzle Kit (PostgreSQL)**
```typescript
// drizzle/schema.ts - Define the PCI DSS tables in your Drizzle schema
import { pgTable, uuid, varchar, timestamp, boolean, text, index } from 'drizzle-orm/pg-core';

export const pciPasswordHistory = pgTable('pciPasswordHistory', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('userId').notNull().references(() => user.id, { onDelete: 'cascade' }),
  passwordHash: varchar('passwordHash', { length: 255 }).notNull(),
  createdAt: timestamp('createdAt').defaultNow()
}, (table) => ({
  userCreatedIdx: index('idx_pci_password_history_user_created').on(table.userId, table.createdAt),
  createdIdx: index('idx_pci_password_history_created').on(table.createdAt)
}));

export const pciUserMetadata = pgTable('pciUserMetadata', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('userId').notNull().unique().references(() => user.id, { onDelete: 'cascade' }),
  lastPasswordChange: timestamp('lastPasswordChange'),
  forcePasswordChange: boolean('forcePasswordChange').default(false),
  lastLoginDate: timestamp('lastLoginDate'),
  createdAt: timestamp('createdAt').defaultNow(),
  updatedAt: timestamp('updatedAt').defaultNow()
}, (table) => ({
  userIdx: index('idx_pci_user_metadata_user').on(table.userId),
  lastPasswordChangeIdx: index('idx_pci_user_metadata_last_password_change').on(table.lastPasswordChange)
}));

export const pciAuditLog = pgTable('pciAuditLog', {
  id: uuid('id').primaryKey().defaultRandom(),
  userId: uuid('userId').notNull().references(() => user.id, { onDelete: 'cascade' }),
  eventType: varchar('eventType', { length: 100 }).notNull(),
  timestamp: timestamp('timestamp').defaultNow(),
  ipAddress: varchar('ipAddress', { length: 45 }),
  userAgent: text('userAgent'),
  metadata: text('metadata')
}, (table) => ({
  userTimestampIdx: index('idx_pci_audit_log_user_timestamp').on(table.userId, table.timestamp),
  eventTimestampIdx: index('idx_pci_audit_log_event_timestamp').on(table.eventType, table.timestamp),
  timestampIdx: index('idx_pci_audit_log_timestamp').on(table.timestamp)
}));
```

```bash
# Generate and apply migration with Drizzle
npx drizzle-kit generate
npx drizzle-kit migrate
```

---

### **🗂️ Database Schema Overview**

#### **Core Tables Structure**

```sql
-- Password History (Ultra-sensitive)
"pciPasswordHistory"
├── id (UUID/VARCHAR(36)/TEXT)
├── userId (UUID/VARCHAR(36)/TEXT) → REFERENCES user(id)
├── passwordHash (VARCHAR(255)) -- PBKDF2-SHA512 format
└── createdAt (TIMESTAMP)

-- User Metadata (Operational)
"pciUserMetadata"
├── id (UUID/VARCHAR(36)/TEXT)
├── userId (UUID/VARCHAR(36)/TEXT) → REFERENCES user(id) UNIQUE
├── lastPasswordChange (TIMESTAMP)
├── forcePasswordChange (BOOLEAN)
├── lastLoginDate (TIMESTAMP)
├── createdAt (TIMESTAMP)
└── updatedAt (TIMESTAMP)

-- Audit Log (Optional)
"pciAuditLog"
├── id (UUID/VARCHAR(36)/TEXT)
├── userId (UUID/VARCHAR(36)/TEXT) → REFERENCES user(id)
├── eventType (VARCHAR(100))
├── timestamp (TIMESTAMP)
├── ipAddress (VARCHAR(45))
├── userAgent (TEXT)
└── metadata (TEXT/JSON)
```

#### **Performance Indexes**
All scripts include essential indexes:
- `idx_pci_password_history_user_created` - User password history queries
- `idx_pci_user_metadata_user` - User metadata lookups
- `idx_pci_audit_log_user_timestamp` - Audit log searches
- `idx_pci_audit_log_event_timestamp` - Event-based queries

---

### **🛠️ Better Auth Supported Databases**

#### **PostgreSQL** (Recommended)
- ✅ Full UUID support with `gen_random_uuid()`
- ✅ Advanced indexing with partial indexes
- ✅ SQL functions for automated cleanup
- ✅ Complete ACID compliance
- ✅ JSON/JSONB support for metadata
- ✅ Best performance for Better Auth workloads
- ✅ Native Better Auth adapter support

#### **MongoDB**
- ✅ NoSQL flexibility for complex user data
- ✅ Automatic schema evolution
- ✅ Built-in replication and sharding
- ✅ Native Better Auth MongoDB adapter
- ✅ TTL indexes for automatic data cleanup
- ⚠️ Different query patterns than SQL
- ⚠️ No SQL migration scripts needed

---

### **📋 Migration Checklist**

#### **Pre-Migration**
- [ ] Choose appropriate SQL script for your database
- [ ] Backup database completely
- [ ] Test migration in staging environment
- [ ] Verify Better Auth user table exists
- [ ] Check database user permissions
- [ ] Plan maintenance window (if production)

#### **During Migration**
- [ ] Execute migration during low-traffic period
- [ ] Monitor migration progress
- [ ] Verify foreign key constraints
- [ ] Check index creation completion
- [ ] Test basic functionality

#### **Post-Migration**
- [ ] Verify all tables created successfully
- [ ] Run verification queries
- [ ] Test password change functionality
- [ ] Configure Better Auth plugin
- [ ] Set up automated cleanup jobs
- [ ] Update documentation
- [ ] Monitor system performance

---

### **🔧 Maintenance Operations**

#### **Data Retention Management**

**PostgreSQL - Automated Functions**
```sql
-- Clean old password history (keep last 4 per user)
SELECT cleanup_password_history(user_id, 4) FROM "user";

-- Clean audit logs older than 1 year
SELECT cleanup_audit_logs(365);
```

**MongoDB - Collection Maintenance**
```javascript
// MongoDB cleanup using the Better Auth MongoDB adapter
// Note: Better Auth handles this automatically with TTL indexes
// Manual cleanup if needed:

// Remove old password history (keep last 4 per user)
db.pciPasswordHistory.aggregate([
  { $sort: { userId: 1, createdAt: -1 } },
  { $group: { _id: "$userId", docs: { $push: "$$ROOT" } } },
  { $project: { toDelete: { $slice: ["$docs", 4, { $size: "$docs" }] } } },
  { $unwind: "$toDelete" },
  { $replaceRoot: { newRoot: "$toDelete" } }
]).forEach(doc => db.pciPasswordHistory.deleteOne({ _id: doc._id }));

// Remove old audit logs (older than 365 days)
db.pciAuditLog.deleteMany({
  timestamp: { $lt: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000) }
});
```
 
#### **Scheduled Maintenance Jobs**

**Cron Job Example (PostgreSQL)**
```bash
#!/bin/bash
# /etc/cron.d/pci-dss-cleanup
# Run daily at 2 AM
0 2 * * * psql -d your_db -c "SELECT cleanup_password_history(id, 4) FROM \"user\";"
0 2 * * * psql -d your_db -c "SELECT cleanup_audit_logs(365);"
```

**Node.js Scheduled Task (PostgreSQL)**
```javascript
// cleanup-scheduler.js
const cron = require('node-cron');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Daily cleanup at 2 AM
cron.schedule('0 2 * * *', async () => {
  console.log('Running PCI DSS data cleanup...');
  
  try {
    // Clean password history (keep last 4 per user)
    await pool.query('SELECT cleanup_password_history(id, 4) FROM "user"');
    
    // Clean audit logs (keep 365 days)
    await pool.query('SELECT cleanup_audit_logs(365)');
    
    console.log('✅ Cleanup completed successfully');
  } catch (error) {
    console.error('❌ Cleanup failed:', error.message);
  }
});

// MongoDB scheduled cleanup (if using MongoDB adapter)
cron.schedule('0 2 * * *', async () => {
  console.log('Running MongoDB PCI DSS data cleanup...');
  
  // Note: Better Auth MongoDB adapter handles TTL automatically
  // Manual cleanup only if needed
});
```

---

### **✅ Post-Migration Verification**

Execute these commands to confirm your migration was successful:

#### **PostgreSQL**
```sql
-- Verify tables were created
SELECT table_name FROM information_schema.tables 
WHERE table_name LIKE 'pci%' ORDER BY table_name;

-- Check table structure
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'pciPasswordHistory';

-- Verify indexes were created
SELECT indexname, tablename FROM pg_indexes 
WHERE indexname LIKE 'idx_pci%' ORDER BY tablename, indexname;
```

#### **MongoDB**
```javascript
// Verify collections were created
db.runCommand("listCollections", { filter: { name: /^pci/ } });

// Check indexes
db.pciPasswordHistory.getIndexes();
db.pciUserMetadata.getIndexes();
db.pciAuditLog.getIndexes();
```

#### **Better Auth Configuration Test**
```typescript
// Test that Better Auth can connect to the new tables
import { auth } from './auth';

// This should not throw errors if tables are set up correctly
const testResult = await auth.api.getSession({
  headers: new Headers(),
});

console.log('✅ Better Auth PCI DSS plugin connected successfully');
```

---

### **⚠️ Security Considerations**

#### **Data Classification**
- **🔴 Ultra-Sensitive**: `pciPasswordHistory` table
  - Contains password hashes
  - Requires encrypted backups
  - Audit all access
  - Implement strict access controls

- **🟡 Sensitive**: `pciUserMetadata` table
  - Contains user security state
  - Monitor for unusual changes
  - Regular access reviews

- **🟢 Operational**: `pciAuditLog` table
  - Security event logs
  - Compliance reporting data
  - Long-term retention policies

#### **Access Control**
```sql
-- Create dedicated database user for the application
CREATE USER pci_app_user WITH PASSWORD 'secure_password';

-- Grant minimal required permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON "pciPasswordHistory" TO pci_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON "pciUserMetadata" TO pci_app_user;
GRANT SELECT, INSERT ON "pciAuditLog" TO pci_app_user;

-- Revoke unnecessary permissions
REVOKE CREATE, DROP, ALTER ON SCHEMA public FROM pci_app_user;
```

#### **Monitoring & Alerting**
```sql
-- Example monitoring queries
-- Detect unusual password change patterns
SELECT 
    userId,
    COUNT(*) as change_count,
    MAX(createdAt) as last_change
FROM "pciPasswordHistory" 
WHERE createdAt > NOW() - INTERVAL '24 hours'
GROUP BY userId
HAVING COUNT(*) > 5;

-- Monitor audit log for security events
SELECT 
    eventType,
    COUNT(*) as event_count
FROM "pciAuditLog"
WHERE timestamp > NOW() - INTERVAL '1 hour'
GROUP BY eventType
HAVING COUNT(*) > threshold_value;
```

---

### **🐛 Common Issues & Solutions**

#### **Migration Failures**

**Issue**: Foreign key constraint violation
```sql
-- Solution: Verify user table structure
SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name = 'user' AND column_name = 'id';
```

**Issue**: Permission denied creating tables
```sql
-- Solution: Grant appropriate permissions
GRANT CREATE ON DATABASE your_database TO migration_user;
-- or for specific schema
GRANT CREATE ON SCHEMA public TO migration_user;
```

**Issue**: Index creation timeout
```sql
-- Solution: Create indexes concurrently (PostgreSQL)
CREATE INDEX CONCURRENTLY "idx_pci_password_history_user_created" 
ON "pciPasswordHistory"("userId", "createdAt" DESC);
```

#### **Performance Issues**

**Issue**: Slow password history queries
```sql
-- Solution: Verify indexes exist and are being used
EXPLAIN ANALYZE SELECT * FROM "pciPasswordHistory" 
WHERE "userId" = 'user-uuid' ORDER BY "createdAt" DESC LIMIT 4;
```

**Issue**: Large table maintenance
```sql
-- Solution: Implement partitioning (PostgreSQL)
CREATE TABLE "pciPasswordHistory" (
    -- ... columns
) PARTITION BY RANGE (createdAt);

CREATE TABLE "pciPasswordHistory_2024" PARTITION OF "pciPasswordHistory"
FOR VALUES FROM ('2024-01-01') TO ('2025-01-01');
```

---

### **📊 Monitoring & Metrics**

#### **Key Performance Indicators**
- Password change frequency
- History validation success rate
- Audit log growth rate
- Database query performance
- Failed login attempts
- Policy violation incidents

#### **Health Check Queries**
```sql
-- Table sizes and growth
SELECT 
    table_name,
    row_estimate,
    total_bytes,
    index_bytes,
    toast_bytes,
    table_bytes
FROM (
    SELECT 
        table_name,
        reltuples::BIGINT AS row_estimate,
        pg_total_relation_size(C.oid) AS total_bytes,
        pg_indexes_size(C.oid) AS index_bytes,
        pg_total_relation_size(reltoastrelid) AS toast_bytes,
        pg_relation_size(C.oid) AS table_bytes
    FROM pg_class C
    LEFT JOIN pg_namespace N ON (N.oid = C.relnamespace)
    WHERE nspname NOT IN ('pg_catalog', 'information_schema')
    AND C.relkind <> 'i'
    AND nspname !~ '^pg_toast'
    AND table_name LIKE 'pci%'
) AS summary
ORDER BY total_bytes DESC;
```

---

> **⚠️ Critical**: Always test migration in staging environment first. Keep database backups. Plan maintenance window for production deployment. 