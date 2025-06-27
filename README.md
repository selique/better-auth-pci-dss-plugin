# Better Auth PCI DSS Plugin 🔐

Plugin for Better Auth that implements PCI DSS-compliant password policies, prioritizing **security by design** and **prevention of sensitive data leakage**.

## 🚨 **Security Architecture**

### **Problem Identified**
The previous implementation stored sensitive data in the `user` table, which is **automatically exposed** in Better Auth API endpoints (`getSession`, `signUpEmail`, etc.), creating a **critical security vulnerability**.

### **Solution Implemented**
Complete refactoring using **separation of concerns**:

- **`pciPasswordHistory`**: Dedicated table for password history (ultra-sensitive data)
- **`pciUserMetadata`**: Table for non-sensitive operational metadata
- **`user` table**: Kept clean, without PCI DSS sensitive data

## 📊 **Database Schema**

```sql
-- 🔐 Ultra-sensitive data (isolated)
CREATE TABLE pciPasswordHistory (
  id UUID PRIMARY KEY,
  userId UUID REFERENCES users(id) ON DELETE CASCADE,
  passwordHash VARCHAR(255) NOT NULL,
  createdAt TIMESTAMP WITH TIME ZONE
);

-- 📋 Operational metadata (non-sensitive)
CREATE TABLE pciUserMetadata (
  id UUID PRIMARY KEY,
  userId UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  lastPasswordChange TIMESTAMP,
  forcePasswordChange BOOLEAN DEFAULT false,
  lastLoginDate TIMESTAMP,
  createdAt TIMESTAMP,
  updatedAt TIMESTAMP
);

-- 📝 Optional: Audit trail (when enabled)
CREATE TABLE pciAuditLog (
  id UUID PRIMARY KEY,
  userId UUID REFERENCES users(id) ON DELETE CASCADE,
  eventType VARCHAR(100) NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE,
  ipAddress VARCHAR(45),
  userAgent TEXT,
  metadata TEXT -- JSON string
);
```

## 🔧 **Installation & Basic Usage**

```bash
npm install better-auth-pci-dss-plugin
```

### **Basic Configuration**
```typescript
import { betterAuth } from 'better-auth';
import { pciDssPasswordPolicy } from 'better-auth-pci-dss-plugin';

export const auth = betterAuth({
  plugins: [
    pciDssPasswordPolicy({
      passwordHistoryCount: 4,           // Last 4 passwords remembered
      passwordChangeIntervalDays: 90,    // Force change every 90 days
      inactiveAccountDeactivationDays: 180,
      forcePasswordChangeOnFirstLogin: true,
    }),
  ],
  // ... other Better Auth config
});
```

## 🔐 **Advanced Security Features**

### **Complete Security Configuration**
```typescript
import { betterAuth } from 'better-auth';
import { pciDssPasswordPolicy } from 'better-auth-pci-dss-plugin';
import winston from 'winston'; // or your preferred logger

// Create secure logger
const securityLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ 
      filename: 'security-events.log',
      level: 'info'
    }),
    new winston.transports.File({ 
      filename: 'security-errors.log',
      level: 'error'
    }),
  ],
});

export const auth = betterAuth({
  plugins: [
    pciDssPasswordPolicy({
      // 📋 Core PCI DSS Requirements
      passwordHistoryCount: 12,         // Remember last 12 passwords
      passwordChangeIntervalDays: 90,   // 90-day password rotation
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
      
      // 🔐 Advanced Security Features
      security: {
        // 📝 Security Logging
        logger: securityLogger,
        
        // 🚨 Security Alerts & Monitoring
        alerts: {
          passwordHistoryViolations: {
            threshold: 3,                 // Alert after 3 violations
            timeWindow: '1 hour',         // Within 1 hour
            action: 'alert',
            callback: async (event) => {
              // Custom alert handler - send to security team
              await notifySecurityTeam('Password History Violation', {
                userId: event.userId,
                timestamp: event.timestamp,
                eventCount: event.metadata.eventCount,
              });
            },
          },
          
          multipleFailedAttempts: {
            threshold: 5,                 // Block after 5 failed attempts
            timeWindow: '15 minutes',     // Within 15 minutes
            action: 'block',
            callback: async (event) => {
              // Auto-lock account temporarily
              await temporarilyLockAccount(event.userId, '30 minutes');
            },
          },
          
          massPasswordChanges: {
            threshold: 100,               // Alert if 100+ password changes
            timeWindow: '1 hour',         // Within 1 hour (possible attack)
            action: 'alert',
            callback: async (event) => {
              await alertSecurityTeam('CRITICAL: Mass Password Change Detected');
            },
          },
        },
        
        // 🗄️ Data Retention Policies
        dataRetention: {
          passwordHistory: {
            retainCount: 12,              // Keep exactly 12 password history entries
            maxAge: '2 years',            // Maximum 2 years retention
          },
          auditLogs: {
            retainPeriod: '7 years',      // PCI DSS compliance requirement
            cleanupInterval: '1 day',     // Daily cleanup of old events
          },
        },
        
        // 📊 Security Metrics & Tracking
        metrics: {
          trackFailedAttempts: true,      // Track authentication failures
          trackPasswordChanges: true,     // Track all password changes
          trackHistoryViolations: true,   // Track password reuse attempts
          trackForceChanges: true,        // Track forced password changes
        },
        
        // 📝 Comprehensive Audit Trail
        auditTrail: true,                 // Enable detailed audit logging
        
        // 🚫 Rate Limiting Protection
        rateLimit: {
          enabled: true,
          maxAttempts: 3,                 // Max 3 password change attempts
          windowMs: 15 * 60 * 1000,      // Per 15-minute window
        },
      },
    }),
  ],
  
  // ... other Better Auth config
});
```

### **Security Event Monitoring**
```typescript
// Example: Real-time security monitoring
async function setupSecurityMonitoring() {
  // Monitor security events in real-time
  securityLogger.on('data', (logEntry) => {
    const event = JSON.parse(logEntry);
    
    // Critical security events
    if (event.level === 'warn' && event.message.includes('Security alert triggered')) {
      // Send to security dashboard
      sendToSecurityDashboard(event);
      
      // Check if immediate action needed
      if (event.message.includes('mass password changes')) {
        triggerIncidentResponse(event);
      }
    }
    
    // Password history violations
    if (event.message.includes('Password history violation')) {
      // Track user behavior patterns
      trackSuspiciousActivity(event.userId);
    }
  });
}
```

### **Compliance Reporting**
```typescript
// Example: Generate PCI DSS compliance reports
async function generateComplianceReport(startDate: Date, endDate: Date) {
  return {
    passwordPolicy: {
      historyCount: 12,
      changeInterval: '90 days',
      forceFirstLogin: true,
    },
    securityEvents: {
      passwordChanges: await getPasswordChangeCount(startDate, endDate),
      historyViolations: await getHistoryViolationCount(startDate, endDate),
      forcedChanges: await getForcedChangeCount(startDate, endDate),
      suspiciousActivity: await getSuspiciousActivityCount(startDate, endDate),
    },
    dataRetention: {
      passwordHistoryRetained: 12,
      auditLogRetention: '7 years',
      lastCleanup: await getLastCleanupDate(),
    },
  };
}
```

## 📋 **API Integration**

### **Checking User Security Status**
```typescript
// Check if user needs password change
async function checkUserSecurityStatus(userId: string) {
  const userMetadata = await db.pciUserMetadata.findUnique({
    where: { userId }
  });
  
  return {
    forcePasswordChange: userMetadata?.forcePasswordChange || false,
    lastPasswordChange: userMetadata?.lastPasswordChange,
    lastLoginDate: userMetadata?.lastLoginDate,
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

### **Password Strength Validation**
```typescript
// Client-side password validation (complementary to server-side)
function validatePasswordStrength(password: string): {
  isValid: boolean;
  errors: string[];
  strength: 'weak' | 'medium' | 'strong' | 'very-strong';
} {
  const errors: string[] = [];
  
  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }
  
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain uppercase letters');
  }
  
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain lowercase letters');
  }
  
  if (!/\d/.test(password)) {
    errors.push('Password must contain numbers');
  }
  
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain special characters');
  }
  
  // Check against common passwords
  if (commonPasswords.includes(password.toLowerCase())) {
    errors.push('Password is too common');
  }
  
  const strength = calculatePasswordStrength(password);
  
  return {
    isValid: errors.length === 0,
    errors,
    strength,
  };
}
```

## 🛡️ **Security Best Practices Implementation**

### **Database Security**
```typescript
// Example: Database connection with security
const dbConfig = {
  url: process.env.DATABASE_URL,
  ssl: {
    require: true,
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-certificate.crt').toString(),
  },
};

// Encryption at rest (example with additional field encryption)
import { encrypt, decrypt } from './crypto-utils';

async function storeAuditLogSecurely(userId: string, eventData: any) {
  const encryptedMetadata = encrypt(JSON.stringify(eventData));
  
  await db.pciAuditLog.create({
    data: {
      userId,
      eventType: eventData.type,
      timestamp: new Date(),
      ipAddress: eventData.ipAddress,
      userAgent: eventData.userAgent,
      metadata: encryptedMetadata, // Encrypted sensitive metadata
    },
  });
}
```

### **Error Handling & Security**
```typescript
// Secure error handling middleware
export function securityErrorHandler(error: any, req: any, res: any, next: any) {
  // Log full error details securely
  securityLogger.error('Application error', {
    error: error.message,
    stack: error.stack,
    userId: req.user?.id,
    path: req.path,
    method: req.method,
    ip: req.ip,
    timestamp: new Date().toISOString(),
  });
  
  // Return generic error to user (no sensitive information)
  if (error.message?.includes('Password cannot be one of the last')) {
    res.status(400).json({
      error: 'Password does not meet security requirements',
      code: 'PASSWORD_POLICY_VIOLATION',
    });
  } else {
    res.status(500).json({
      error: 'An error occurred. Please try again.',
      code: 'INTERNAL_ERROR',
    });
  }
}
```

### **Monitoring Dashboard Integration**
```typescript
// Example: Security metrics for dashboard
export async function getSecurityMetrics(timeRange: '24h' | '7d' | '30d') {
  const startDate = getDateFromRange(timeRange);
  
  return {
    passwordChanges: await getPasswordChangeMetrics(startDate),
    securityViolations: await getSecurityViolationMetrics(startDate),
    userActivity: await getUserActivityMetrics(startDate),
    systemHealth: await getSystemHealthMetrics(startDate),
    alerts: {
      critical: await getCriticalAlerts(startDate),
      warnings: await getWarningAlerts(startDate),
    },
  };
}
```

## 📝 **Quick Migration**

For detailed migration instructions, see [MIGRATION.md](./MIGRATION.md).

### **Fresh Installation**
```bash
npm install better-auth-pci-dss-plugin bcrypt
```

### **Upgrading from v1.x**
```bash
# 1. Backup database first!
pg_dump your_database > backup.sql

# 2. Update dependencies
npm install better-auth-pci-dss-plugin@latest

# 3. Run migration (see MIGRATION.md for full details)
# 4. Test thoroughly before production deployment
```

## 🚀 **Production Deployment**

### **Environment Variables**
```bash
# Database
DATABASE_URL="postgresql://user:password@host:5432/database?sslmode=require"

# Better Auth
BETTER_AUTH_SECRET="your-super-secure-256-bit-key"
BETTER_AUTH_URL="https://yourdomain.com"

# Security
SECURITY_LOG_LEVEL="info"
SECURITY_ALERT_WEBHOOK="https://your-security-webhook.com"
ENCRYPTION_KEY="your-encryption-key-for-sensitive-data"

# Rate Limiting
REDIS_URL="redis://localhost:6379" # For distributed rate limiting
```

### **Docker Configuration**
```dockerfile
# Security-hardened container
FROM node:18-alpine

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Install security updates
RUN apk update && apk upgrade

# Set secure permissions
WORKDIR /app
COPY --chown=appuser:appgroup . .

USER appuser

# Health check for security monitoring
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000
CMD ["npm", "start"]
```

### **Monitoring & Alerts**
```yaml
# Example: Prometheus metrics
- name: pci_dss_password_changes_total
  help: Total number of password changes
  type: counter
  
- name: pci_dss_history_violations_total  
  help: Total number of password history violations
  type: counter
  
- name: pci_dss_forced_changes_total
  help: Total number of forced password changes
  type: counter

# Example: Alert rules
- alert: HighPasswordHistoryViolations
  expr: increase(pci_dss_history_violations_total[5m]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "High number of password history violations detected"
```

## 🔒 **Security Considerations**

### **Production Checklist**
- [ ] **HTTPS enforced** for all connections
- [ ] **Database encryption** at rest enabled
- [ ] **Secrets management** (no hardcoded secrets)
- [ ] **Security logging** configured and monitored
- [ ] **Rate limiting** implemented
- [ ] **Error handling** secure (no information leakage)
- [ ] **Backup procedures** tested and secured
- [ ] **Access controls** properly configured
- [ ] **Security headers** implemented
- [ ] **Monitoring and alerting** active

### **Compliance Features**
- ✅ **PCI DSS 8.2.1**: Strong cryptographic algorithms (bcrypt)
- ✅ **PCI DSS 8.2.3**: Secure password history mechanism  
- ✅ **PCI DSS 8.2.4**: Regular password changes enforced
- ✅ **PCI DSS 8.2.5**: First-time password must be changed
- ✅ **PCI DSS 8.2.6**: Password complexity requirements
- ✅ **Data isolation**: Sensitive data not exposed via API
- ✅ **Audit trail**: Comprehensive security event logging
- ✅ **Access controls**: Proper database permissions

## 📚 **Documentation**

- [Migration Guide](./MIGRATION.md) - **Start here for upgrades**
- [Security Best Practices](./SECURITY.md)
- [Contributing Guide](./CONTRIBUTING.md)

## 🤝 **Contributing**

See [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines on contributing to this project.

## 📜 **License**

MIT License - see [LICENSE](./LICENSE) file for details.

---

> **🔐 Security First**: This plugin prioritizes security by design, implementing defense-in-depth strategies and following PCI DSS compliance requirements. All sensitive data is properly isolated and never exposed through user-facing APIs. 