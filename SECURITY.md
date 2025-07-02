# Security Best Practices 🔐

Production security guidelines for the Better Auth PCI DSS Plugin.

## 🛡️ **Core Principles**

- **Defense in Depth**: Multiple security layers, no single point of failure
- **Least Privilege**: Minimum necessary permissions, regular access audits
- **Data Minimization**: Store only required data, implement retention policies

## 🔒 **Password Security**

### **Hashing Standards**
```typescript
// ✅ Use PBKDF2-SHA512 (Node.js crypto, compatible with better-auth)
import { pbkdf2, randomBytes } from 'crypto';

const salt = randomBytes(32);
const hashedPassword = pbkdf2(password, salt, 10000, 64, 'sha512');

// ❌ Never use: plaintext, MD5, SHA1, weak algorithms
```

### **Storage Requirements**
- Never log passwords (plaintext or hashed)
- Use dedicated tables for password history
- Implement database encryption at rest
- Separate sensitive data from user profiles

## 🗄️ **Database Security**

### **Table Isolation**
```sql
-- ✅ Correct: Isolated sensitive data
CREATE TABLE pciPasswordHistory (
  id UUID PRIMARY KEY,
  userId UUID REFERENCES users(id) ON DELETE CASCADE,
  passwordHash VARCHAR(255) NOT NULL,
  createdAt TIMESTAMP WITH TIME ZONE
);

-- ❌ Wrong: Sensitive data in main user table
ALTER TABLE users ADD COLUMN password_history TEXT[];
```

### **Access Control**
```sql
-- Dedicated database user with minimal permissions
CREATE USER pci_app_user WITH PASSWORD 'strong_random_password';

GRANT SELECT, INSERT, UPDATE, DELETE ON pciPasswordHistory TO pci_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON pciUserMetadata TO pci_app_user;
GRANT SELECT, UPDATE ON users TO pci_app_user; -- Read-only on main table

REVOKE ALL ON schema_migrations FROM pci_app_user;
```

### **Connection Security**
```typescript
const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: { require: true, rejectUnauthorized: true },
};
```

## 🌐 **Network & API Security**

### **Essential Controls**
- Rate limiting on authentication endpoints
- IP whitelisting for admin functions
- Request size limits (DoS prevention)
- CORS configuration for cross-origin requests
- HTTPS enforcement for all connections

### **Security Headers**
```typescript
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});
```

## 🔐 **Secrets Management**

### **Environment Variables**
```bash
# ✅ Strong, unique secrets
BETTER_AUTH_SECRET=crypto_random_256_bit_key
DB_PASSWORD=strong_unique_database_password
ENCRYPTION_KEY=another_crypto_random_256_bit_key

# ❌ Never use weak/default secrets
```

### **Secret Rotation Schedule**
- Auth secrets: 90 days
- Database passwords: 180 days
- Encryption keys: 365 days

## 📊 **Monitoring & Auditing**

### **Security Event Logging**
```typescript
const securityLogger = {
  passwordChangeAttempt: (userId: string, success: boolean, req: any) => {
    logger.info('Password change attempt', {
      userId, success,
      timestamp: new Date().toISOString(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
  },
  
  passwordHistoryViolation: (userId: string, req: any) => {
    logger.warn('Password history violation', {
      userId,
      timestamp: new Date().toISOString(),
      ipAddress: req.ip,
    });
  },
};
```

### **Critical Metrics**
- Failed authentication attempts per user/IP
- Password change frequency patterns
- Force password change events
- Database connection anomalies
- Unusual access patterns

### **Alert Configuration**
```typescript
const securityAlerts = {
  multipleFailedAttempts: {
    threshold: 5,
    timeWindow: '15 minutes',
    action: 'temporarily_lock_account',
  },
  
  passwordHistoryViolations: {
    threshold: 3,
    timeWindow: '1 hour',
    action: 'alert_security_team',
  },
  
  massPasswordChanges: {
    threshold: 100,
    timeWindow: '1 hour',
    action: 'alert_admin_immediately',
  },
};
```

## 🚀 **Production Deployment**

### **Pre-Deployment Checklist**
- [ ] HTTPS enforced for all connections
- [ ] Database encryption at rest enabled
- [ ] Secrets properly managed (no hardcoded values)
- [ ] Security logging configured and monitored
- [ ] Rate limiting implemented
- [ ] Error handling secure (no information leakage)
- [ ] Backup procedures tested
- [ ] Access controls configured
- [ ] Security headers implemented
- [ ] Monitoring and alerting active

### **Error Handling**
```typescript
// ✅ Secure error handling
try {
  await validatePasswordHistory(password, userId);
} catch (error) {
  logger.error('Password validation error', { error, userId });
  throw new Error('Password does not meet requirements'); // Generic message
}

// ❌ Insecure: exposing internal details
catch (error) {
  throw new Error(`Database error: ${error.message}`);
}
```

## 📋 **Compliance Requirements**

### **PCI DSS Implementation**
- **8.2.1**: Strong cryptographic algorithms (PBKDF2-SHA512, NIST approved)
- **8.2.3**: Secure password history mechanism (dedicated tables)
- **8.2.4**: Regular password changes enforced (configurable intervals)
- **8.2.5**: First-time password must be changed (force flag)
- **8.2.6**: Password complexity requirements (configurable policies)

### **Data Retention**
```typescript
const retentionPolicy = {
  passwordHistory: {
    retainCount: 12, // Last 12 passwords
    maxAge: '2 years', // Absolute maximum
  },
  
  auditLogs: {
    retainPeriod: '7 years', // Compliance requirement
    cleanupInterval: '1 day',
  },
};
```

## 🚨 **Incident Response**

### **Security Incident Types**
1. **Data Breach**: Unauthorized access to sensitive data
2. **Brute Force Attack**: Multiple failed login attempts
3. **Privilege Escalation**: Unauthorized permission changes
4. **Data Corruption**: Integrity violations

### **Response Procedures**
1. **Detection**: Automated alerts, monitoring dashboards
2. **Containment**: Isolate systems, revoke credentials, preserve evidence
3. **Eradication**: Remove threats, patch vulnerabilities, update controls
4. **Recovery**: Restore from backups, verify integrity, monitor

## 🔍 **Security Testing**

### **Regular Security Tests**
```bash
# Static code analysis
npm audit
snyk test

# Dependency vulnerability scanning
npm ls --audit-level moderate

# SSL/TLS testing
testssl.sh yourdomain.com
```

### **Penetration Testing Areas**
- Authentication bypass attempts
- SQL injection testing
- Cross-site scripting (XSS)
- Session management testing
- Input validation testing
- Error handling security

## 📚 **Security Resources**

### **Standards & Guidelines**
- [OWASP Top 10](https://owasp.org/Top10/)
- [PCI DSS Standards](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### **Security Tools**
- **Static Analysis**: ESLint security plugins, Semgrep
- **Dependency Scanning**: Snyk, npm audit
- **Runtime Protection**: Helmet.js, express-rate-limit
- **Monitoring**: SIEM solutions, security dashboards

---

> **⚠️ Important**: These are general guidelines. Always consult security professionals and conduct regular assessments for your specific environment.

> **🔄 Updates**: Review and update this document quarterly or after security incidents.
