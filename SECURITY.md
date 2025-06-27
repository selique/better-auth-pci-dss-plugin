# Security Best Practices 🔐

This document outlines security best practices for implementing and maintaining the Better Auth PCI DSS Plugin in production environments.

## 🛡️ **Core Security Principles**

### **Defense in Depth**
- Multiple layers of security controls
- No single point of failure
- Assume breach scenarios and plan accordingly

### **Principle of Least Privilege**
- Grant minimum necessary permissions
- Regularly audit and review access rights
- Use role-based access control (RBAC)

### **Data Minimization**
- Store only required data
- Implement data retention policies
- Regular cleanup of unnecessary historical data

## 🔒 **Password Security**

### **Hash Algorithm Standards**
```typescript
// ✅ Recommended: Use bcrypt with appropriate cost factor
const saltRounds = 12; // Adjust based on hardware capabilities
const hashedPassword = await bcrypt.hash(password, saltRounds);

// ❌ Never use: Plain text, MD5, SHA1, or weak algorithms
```

### **Password Policy Enforcement**
```typescript
// Implement comprehensive password requirements
const passwordPolicy = {
  minLength: 12,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  prohibitCommonPasswords: true,
  prohibitUserInfo: true, // No name, email in password
};
```

### **Secure Password Storage**
- **Never log passwords** in any form (plaintext or hashed)
- **Separate sensitive data** from user profiles
- **Use dedicated tables** for password history
- **Implement proper database encryption** at rest

## 🗄️ **Database Security**

### **Table Isolation**
```sql
-- ✅ Correct: Dedicated tables for sensitive data
CREATE TABLE pciPasswordHistory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  userId UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  passwordHash VARCHAR(255) NOT NULL,
  createdAt TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  INDEX idx_user_created (userId, createdAt DESC)
);

-- ❌ Wrong: Sensitive data in main user table
ALTER TABLE users ADD COLUMN password_history TEXT[];
```

### **Database Access Control**
```sql
-- Create dedicated database user for application
CREATE USER pci_app_user WITH PASSWORD 'strong_random_password';

-- Grant minimal required permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON pciPasswordHistory TO pci_app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON pciUserMetadata TO pci_app_user;
GRANT SELECT, UPDATE ON users TO pci_app_user; -- Read-only on main user table

-- Revoke unnecessary permissions
REVOKE ALL ON schema_migrations FROM pci_app_user;
REVOKE ALL ON sensitive_admin_tables FROM pci_app_user;
```

### **Database Encryption**
- **Enable encryption at rest** for all database storage
- **Use TLS/SSL** for all database connections
- **Encrypt sensitive columns** with application-level encryption if required

## 🌐 **Network Security**

### **Connection Security**
```typescript
// ✅ Secure database connection
const dbConfig = {
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  ssl: {
    require: true,
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-certificate.crt').toString(),
  },
};
```

### **API Security**
- **Rate limiting** on authentication endpoints
- **IP whitelisting** for administrative functions
- **Request size limits** to prevent DoS attacks
- **CORS configuration** for cross-origin requests

## 🔐 **Secrets Management**

### **Environment Variables**
```bash
# ✅ Use strong, unique secrets
BETTER_AUTH_SECRET=crypto_random_256_bit_key
DB_PASSWORD=strong_unique_database_password
ENCRYPTION_KEY=another_crypto_random_256_bit_key

# ❌ Never use: Weak or default secrets
BETTER_AUTH_SECRET=secret123
DB_PASSWORD=password
```

### **Secret Rotation**
```typescript
// Implement regular secret rotation
const secretRotationSchedule = {
  authSecret: '90 days',
  databasePassword: '180 days',
  encryptionKeys: '365 days',
};

// Use versioned secrets for zero-downtime rotation
const currentSecret = process.env.BETTER_AUTH_SECRET_V2;
const previousSecret = process.env.BETTER_AUTH_SECRET_V1;
```

## 📊 **Monitoring and Auditing**

### **Security Event Logging**
```typescript
// Log security-relevant events
const securityLogger = {
  passwordChangeAttempt: (userId: string, success: boolean) => {
    logger.info('Password change attempt', {
      userId,
      success,
      timestamp: new Date().toISOString(),
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
    });
  },
  
  passwordHistoryViolation: (userId: string) => {
    logger.warn('Password history violation', {
      userId,
      timestamp: new Date().toISOString(),
      ipAddress: req.ip,
    });
  },
  
  forcePasswordChangeTriggered: (userId: string, reason: string) => {
    logger.info('Force password change triggered', {
      userId,
      reason,
      timestamp: new Date().toISOString(),
    });
  },
};
```

### **Metrics to Monitor**
- Failed authentication attempts per user/IP
- Password change frequency patterns
- Force password change events
- Database connection anomalies
- Unusual access patterns

### **Alerting Configuration**
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

### **Environment Checklist**
- [ ] **HTTPS enforced** for all connections
- [ ] **Database encryption** enabled
- [ ] **Secrets properly managed** (not in code)
- [ ] **Monitoring and logging** configured
- [ ] **Backup and recovery** procedures tested
- [ ] **Security headers** implemented
- [ ] **Rate limiting** configured
- [ ] **Error handling** doesn't leak sensitive information

### **Security Headers**
```typescript
// Implement security headers
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
```

### **Error Handling**
```typescript
// ✅ Secure error handling
try {
  await validatePasswordHistory(password, userId);
} catch (error) {
  // Log full error for debugging
  logger.error('Password validation error', { error, userId });
  
  // Return generic error to user
  throw new Error('Password does not meet requirements');
}

// ❌ Insecure: Exposing internal details
catch (error) {
  throw new Error(`Database error: ${error.message}`);
}
```

## 📋 **Compliance Considerations**

### **PCI DSS Requirements**
- **8.2.1**: Use strong cryptographic algorithms
- **8.2.3**: Secure password history mechanism
- **8.2.4**: Regular password changes enforced
- **8.2.5**: First-time password must be changed
- **8.2.6**: Password complexity requirements

### **Data Retention**
```typescript
// Implement compliant data retention
const retentionPolicy = {
  passwordHistory: {
    retainCount: 12, // Last 12 passwords
    maxAge: '2 years', // Absolute maximum retention
  },
  
  auditLogs: {
    retainPeriod: '7 years', // Compliance requirement
    archiveAfter: '2 years',
  },
  
  sessionData: {
    maxAge: '24 hours',
    cleanupInterval: '1 hour',
  },
};
```

### **Regular Security Tasks**
```typescript
// Scheduled security maintenance
const securityTasks = {
  daily: [
    'cleanup_expired_sessions',
    'review_failed_login_attempts',
    'check_security_alerts',
  ],
  
  weekly: [
    'cleanup_old_password_history',
    'review_access_logs',
    'update_security_dashboards',
  ],
  
  monthly: [
    'security_vulnerability_scan',
    'review_user_permissions',
    'test_backup_procedures',
  ],
  
  quarterly: [
    'security_audit',
    'penetration_testing',
    'compliance_review',
  ],
};
```

## 🚨 **Incident Response**

### **Security Incident Types**
1. **Data Breach**: Unauthorized access to sensitive data
2. **Brute Force Attack**: Multiple failed login attempts
3. **Privilege Escalation**: Unauthorized permission changes
4. **Data Corruption**: Integrity violations in sensitive data

### **Response Procedures**
```typescript
const incidentResponse = {
  detection: {
    automated_alerts: true,
    monitoring_dashboards: true,
    user_reports: true,
  },
  
  containment: {
    isolate_affected_systems: true,
    revoke_compromised_credentials: true,
    preserve_evidence: true,
  },
  
  eradication: {
    remove_threat_vectors: true,
    patch_vulnerabilities: true,
    update_security_controls: true,
  },
  
  recovery: {
    restore_from_backups: true,
    verify_system_integrity: true,
    monitor_for_recurring_issues: true,
  },
};
```

## 🔍 **Security Testing**

### **Regular Security Tests**
```bash
# Static code analysis
npm audit
snyk test

# Dependency vulnerability scanning
npm ls --audit-level moderate

# Database security testing
sqlmap -u "database_connection_string" --batch

# SSL/TLS configuration testing
testssl.sh yourdomain.com
```

### **Penetration Testing Checklist**
- [ ] Authentication bypass attempts
- [ ] SQL injection testing
- [ ] Cross-site scripting (XSS)
- [ ] Cross-site request forgery (CSRF)
- [ ] Session management testing
- [ ] Input validation testing
- [ ] Error handling testing

## 📚 **Security Resources**

### **Standards and Guidelines**
- [OWASP Top 10](https://owasp.org/Top10/)
- [PCI DSS Standards](https://www.pcisecuritystandards.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)

### **Security Tools**
- **Static Analysis**: ESLint security plugins, Semgrep
- **Dependency Scanning**: Snyk, npm audit, OWASP Dependency Check
- **Runtime Protection**: Helmet.js, express-rate-limit
- **Monitoring**: Security event correlation tools, SIEM solutions

### **Training and Awareness**
- Regular security training for development team
- Secure coding practices workshops
- Incident response drills
- Compliance training updates

---

> **⚠️ Important**: This document provides general security guidelines. Always consult with security professionals and conduct regular security assessments for your specific environment and requirements.

> **🔄 Updates**: Review and update this document quarterly or after any security incidents or significant system changes.
