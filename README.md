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

### **`pciPasswordHistory` Table**
```sql
CREATE TABLE pciPasswordHistory (
  id VARCHAR PRIMARY KEY,
  userId VARCHAR NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  passwordHash VARCHAR NOT NULL,
  createdAt TIMESTAMP NOT NULL
);
```

### **`pciUserMetadata` Table**
```sql
CREATE TABLE pciUserMetadata (
  id VARCHAR PRIMARY KEY,
  userId VARCHAR UNIQUE NOT NULL REFERENCES user(id) ON DELETE CASCADE,
  lastPasswordChange TIMESTAMP,
  forcePasswordChange BOOLEAN DEFAULT FALSE,
  lastLoginDate TIMESTAMP,
  createdAt TIMESTAMP NOT NULL,
  updatedAt TIMESTAMP NOT NULL
);
```

## 🔧 **Configuration**

```typescript
import { betterAuth } from "better-auth";
import { pciDssPasswordPolicy } from "better-auth-pci-dss-plugin";

export const auth = betterAuth({
  // ... other Better Auth configurations
  plugins: [
    pciDssPasswordPolicy({
      passwordHistoryCount: 12,           // History of last 12 passwords
      passwordChangeIntervalDays: 90,     // Force change every 90 days
      inactiveAccountDeactivationDays: 365,
      forcePasswordChangeOnFirstLogin: true
    })
  ]
});
```

## 🛡️ **PCI DSS Requirements Implemented**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **8.2.3** - Password history | ✅ | `pciPasswordHistory` table with bcrypt hash |
| **8.2.4** - Periodic renewal | ✅ | Controlled by `passwordChangeIntervalDays` |
| **8.2.5** - Temporary first password | ✅ | `forcePasswordChangeOnFirstLogin` flag |
| **8.2.6** - Password complexity | ⚠️ | Requires additional front-end validation |
| **8.1.8** - Account deactivation | 🔄 | In development |

## 🔄 **Migration from Previous Version**

If you were using the previous version that modified the `user` table:

1. **Run migrations**:
```bash
npx @better-auth/cli migrate
```

2. **Existing data** in the `user` table needs manual migration:
```sql
-- Migrate password history (if exists)
INSERT INTO pciPasswordHistory (userId, passwordHash, createdAt)
SELECT id, UNNEST(passwordHistory), NOW()
FROM user 
WHERE passwordHistory IS NOT NULL;

-- Migrate metadata
INSERT INTO pciUserMetadata (userId, lastPasswordChange, forcePasswordChange, lastLoginDate, createdAt, updatedAt)
SELECT id, lastPasswordChange, forcePasswordChange, lastLoginDate, NOW(), NOW()
FROM user;

-- Clean old fields from user table
ALTER TABLE user 
DROP COLUMN IF EXISTS passwordHistory,
DROP COLUMN IF EXISTS lastPasswordChange,
DROP COLUMN IF EXISTS forcePasswordChange,
DROP COLUMN IF EXISTS lastLoginDate;
```

## 🎯 **Advantages of New Architecture**

### **Security**
- ✅ **Zero exposure** of sensitive data via API
- ✅ **Complete isolation** of password history
- ✅ **Automatic cascade deletion** when user is deleted
- ✅ **Granular access control** per table

### **Performance**
- ✅ **Optimized queries** with specific indexes
- ✅ **Automatic cleanup** of old history
- ✅ **Smaller queries** on main `user` table

### **Compliance**
- ✅ **Data segregation** per PCI DSS
- ✅ **Independent auditing** per table
- ✅ **Controlled retention** of historical data

## 🔍 **Recommended Indexes**

```sql
-- Performance for history queries
CREATE INDEX idx_pci_password_history_user_created 
ON pciPasswordHistory(userId, createdAt DESC);

-- Performance for user metadata
CREATE INDEX idx_pci_user_metadata_user 
ON pciUserMetadata(userId);

-- Cleanup of expired data
CREATE INDEX idx_pci_password_history_created 
ON pciPasswordHistory(createdAt);
```

## 💡 **How It Works**

### **Password History Validation**
- Stores bcrypt-hashed passwords in dedicated `pciPasswordHistory` table
- Validates new passwords against configured history count
- Automatically maintains history size by removing oldest entries

### **Password Expiration**
- Tracks last password change in `pciUserMetadata` table
- Sets `forcePasswordChange` flag when password expires
- Frontend can check this flag to redirect users

### **First Login Requirements**
- Forces password change for new users on first login
- Configurable via `forcePasswordChangeOnFirstLogin` option

## 🔐 **Security Features**

- **No API Exposure**: Sensitive data never appears in user endpoints
- **Bcrypt Hashing**: All password history uses secure hashing
- **Cascade Deletion**: Automatic cleanup when users are deleted
- **Foreign Key Constraints**: Referential integrity maintained
- **Separate Concerns**: Clear separation between sensitive and non-sensitive data

## 📚 **Additional Documentation**

- [PCI DSS Requirements](https://www.pcisecuritystandards.org/)
- [Better Auth Documentation](https://better-auth.com/)
- [Security Best Practices](./SECURITY.md)

## 🤝 **Contributing**

Contributions are welcome! Please read our [contributing guide](./CONTRIBUTING.md) before submitting PRs.

## 📄 **License**

MIT License. See [LICENSE](./LICENSE) for more details.

---

> **⚠️ Notice**: This plugin implements basic PCI DSS requirements. For complete compliance, consult a security specialist and perform regular audits. 