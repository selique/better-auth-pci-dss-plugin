# Better Auth PCI DSS Plugin 🔐

Secure password policy plugin for Better Auth with **enterprise-grade security** and **zero API exposure** of sensitive data.

## 🚨 **Why This Plugin?**

**Problem**: Better Auth plugins that extend the `user` table automatically expose sensitive data through API endpoints (`getSession`, `signUpEmail`, etc.).

**Solution**: Dedicated security tables that isolate sensitive data while maintaining full PCI DSS compliance.

## ⚡ **Quick Start**

```bash
npm install better-auth-pci-dss-plugin
```

```typescript
import { betterAuth } from 'better-auth';
import { pciDssPasswordPolicy } from 'better-auth-pci-dss-plugin';

export const auth = betterAuth({
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

## 🔐 **Security Architecture**

### **Database Tables**
```sql
-- Sensitive data (isolated from APIs)
pciPasswordHistory: id, userId, passwordHash, createdAt
pciUserMetadata: id, userId, lastPasswordChange, forcePasswordChange, lastLoginDate

-- Optional audit trail
pciAuditLog: id, userId, eventType, timestamp, ipAddress, userAgent, metadata
```

### **Core Features**
- ✅ **Password history enforcement** (prevents reuse)
- ✅ **Automatic password expiration** (configurable intervals)
- ✅ **Force password change** (first login, expired passwords)
- ✅ **Zero API exposure** (sensitive data never in user endpoints)
- ✅ **Audit trail** (comprehensive security logging)

### **🔐 Cryptographic Implementation**

**Native Node.js Crypto** - Zero external dependencies, full better-auth compatibility:

```typescript
// Using Node.js crypto (same as better-auth core)
import { pbkdf2, randomBytes } from 'crypto';

// PBKDF2 with SHA512 (NIST recommended)
- Algorithm: PBKDF2-SHA512
- Salt: 256-bit cryptographically secure random
- Iterations: 10,000 (industry standard)
- Key Length: 512-bit derived key
- Format: "salt:iterations:hash" (better-auth compatible)
```

**Security Benefits:**
- ✅ **NIST Approved**: PBKDF2 is FIPS 140-2 compliant
- ✅ **Perfect Integration**: Uses same crypto stack as better-auth
- ✅ **Zero Dependencies**: No external crypto libraries needed
- ✅ **Timing Attack Protection**: Constant-time comparison
- ✅ **Migration Ready**: Seamless upgrade path from bcrypt

## 🛡️ **Advanced Security (Optional)**

Add enterprise features incrementally:

```typescript
pciDssPasswordPolicy({
  // ... basic config
  security: {
    logger: yourLogger,                    // Structured security logging
    auditTrail: true,                     // Comprehensive audit trail
    rateLimit: { enabled: true, maxAttempts: 3 },  // Brute force protection
    
    alerts: {
      passwordHistoryViolations: {
        threshold: 3,
        timeWindow: '1 hour',
        callback: async (event) => await notifySecurityTeam(event),
      },
    },
    
    dataRetention: {
      passwordHistory: { retainCount: 12, maxAge: '2 years' },
      auditLogs: { retainPeriod: '7 years', cleanupInterval: '1 day' },
    },
    
    metrics: {
      trackPasswordChanges: true,
      trackHistoryViolations: true,
      trackForceChanges: true,
    },
  },
})
```

## 📋 **Frontend Integration**

### **Check Security Status**
```typescript
async function checkUserSecurityStatus(userId: string) {
  const metadata = await db.pciUserMetadata.findUnique({ where: { userId } });
  
  return {
    forcePasswordChange: metadata?.forcePasswordChange || false,
    passwordAge: metadata?.lastPasswordChange 
      ? Math.floor((Date.now() - new Date(metadata.lastPasswordChange).getTime()) / (1000 * 60 * 60 * 24))
      : null,
  };
}

// Redirect if password change required
const status = await checkUserSecurityStatus(user.id);
if (status.forcePasswordChange) {
  router.push('/auth/change-password?required=true');
}
```

### **Handle Errors**
```typescript
try {
  await auth.changePassword({ password });
} catch (err) {
  if (err.message.includes('cannot be one of the last')) {
    setError('Password cannot be one of your recent passwords');
  } else if (err.message.includes('Too many password change attempts')) {
    setError('Too many attempts. Please try again later.');
  }
}
```

## 🚀 **Production Setup**

### **Environment Variables**
```bash
DATABASE_URL="postgresql://user:password@host:5432/db?sslmode=require"
BETTER_AUTH_SECRET="your-super-secure-256-bit-key"
SECURITY_WEBHOOK_URL="https://your-security-alerts.com/webhook"
```

### **Database Indexes** (Recommended)
```sql
CREATE INDEX idx_pci_password_history_user_created ON pciPasswordHistory(userId, createdAt DESC);
CREATE INDEX idx_pci_user_metadata_user ON pciUserMetadata(userId);
CREATE INDEX idx_pci_audit_log_user_timestamp ON pciAuditLog(userId, timestamp DESC);
```

### **Security Monitoring**
```typescript
// Real-time security monitoring
securityLogger.on('data', (logEntry) => {
  const event = JSON.parse(logEntry);
  
  if (event.level === 'warn' && event.message.includes('Security alert triggered')) {
    sendToSecurityDashboard(event);
    
    if (event.message.includes('mass password changes')) {
      triggerIncidentResponse(event);
    }
  }
});
```

## 📝 **Integration & Compliance**

### **Adding to Existing Project**
```bash
# 1. Backup database first!
pg_dump your_database > backup.sql

# 2. Install plugin
npm install better-auth-pci-dss-plugin

# 3. See MIGRATION.md for detailed steps
```

### **PCI DSS Compliance**
- ✅ **8.2.1**: Strong cryptographic algorithms (PBKDF2-SHA512, NIST approved)
- ✅ **8.2.3**: Secure password history mechanism
- ✅ **8.2.4**: Regular password changes enforced
- ✅ **8.2.5**: First-time password must be changed
- ✅ **8.2.6**: Password complexity requirements support

### **📋 Migration from Previous Versions**

**Breaking Change Notice**: Version 2.0+ uses Node.js crypto instead of bcrypt.

```typescript
// For existing bcrypt installations, passwords will need reset
// See MIGRATION.md for complete migration guide

// Old bcrypt hashes are gracefully handled:
// 1. User attempts login with bcrypt hash → fails securely
// 2. Force password reset → new PBKDF2 hash created
// 3. Future logins use new secure hash format
```

**Migration Benefits:**
- 🚀 **Faster**: Node.js crypto is optimized for server environments
- 🔗 **Better Integration**: Same crypto stack as better-auth core
- 📦 **Smaller Bundle**: No external dependencies

## 📚 **Documentation**

- **[MIGRATION.md](./MIGRATION.md)** - Complete integration guide with SQL scripts
- **[SECURITY.md](./SECURITY.md)** - Production security best practices
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - Development and contribution guidelines

## 🔒 **Security First**

This plugin prioritizes security by design:
- **Defense in depth** with multiple security layers
- **Data isolation** prevents accidental exposure
- **Audit trail** for compliance and monitoring
- **Rate limiting** prevents brute force attacks
- **Secure defaults** with optional advanced features

---

> **🚨 Important**: Always test in staging first. Keep database backups. Review [SECURITY.md](./SECURITY.md) for production deployment.

## 📜 **License**

MIT License - see [LICENSE](./LICENSE) file for details. 