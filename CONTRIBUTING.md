# Contributing to Better Auth PCI DSS Plugin 🤝

We welcome contributions to the Better Auth PCI DSS Plugin! This document provides guidelines for contributing to the project.

## 📋 **Code of Conduct**

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## 🚀 **Getting Started**

### **Prerequisites**
- Node.js 18+ and npm
- Git
- Understanding of PCI DSS security requirements
- Familiarity with Better Auth framework

### **Development Setup**
```bash
# Clone the repository
git clone https://github.com/your-username/better-auth-pci-dss-plugin.git
cd better-auth-pci-dss-plugin

# Install dependencies
npm install

# Run tests
npm test

# Run linting
npm run lint
```

## 🔧 **Development Guidelines**

### **Security First**
- **Never expose sensitive data** in user-facing APIs
- **Use bcrypt** for all password hashing (minimum cost factor 12)
- **Follow least privilege** principle in database access
- **Validate all inputs** and sanitize outputs
- **Log security events** appropriately (without sensitive data)

### **Code Standards**
```typescript
// ✅ Good: Secure, typed, and clear
interface PCIDSSOptions {
  passwordHistoryCount: number;
  passwordChangeIntervalDays: number;
}

async function validatePasswordHistory(
  password: string,
  userId: string,
  adapter: DatabaseAdapter
): Promise<void> {
  const history = await adapter.findMany({
    model: "pciPasswordHistory",
    where: [{ field: "userId", value: userId }],
    limit: 12,
    orderBy: [{ field: "createdAt", direction: "desc" }],
  });
  
  for (const entry of history) {
    if (await bcrypt.compare(password, entry.passwordHash)) {
      throw new Error("Password cannot be one of the last 12 used passwords");
    }
  }
}

// ❌ Bad: Insecure and unclear
function checkPassword(pwd: any, user: any) {
  if (user.oldPasswords.includes(pwd)) {
    return false;
  }
  return true;
}
```

### **Database Best Practices**
- Use **dedicated tables** for sensitive data
- Implement **proper foreign key constraints**
- Include **cascade deletion** for cleanup
- Add **appropriate indexes** for performance
- Never store **plaintext passwords**

## 🧪 **Testing Requirements**

### **Test Coverage**
All contributions must include comprehensive tests:

```typescript
// Example test structure
describe('Password History Validation', () => {
  it('should reject password that matches history', async () => {
    // Arrange
    const mockAdapter = createMockAdapter();
    const testPassword = 'TestPassword123!';
    
    // Act & Assert
    await expect(
      validatePasswordHistory(testPassword, 'user-123', mockAdapter)
    ).rejects.toThrow('Password cannot be one of the last');
  });
  
  it('should allow password that does not match history', async () => {
    // Test implementation
  });
});
```

### **Security Testing**
- **Input validation** tests for all user inputs
- **SQL injection** prevention verification
- **Access control** boundary testing
- **Error handling** security tests

### **Running Tests**
```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run security-specific tests
npm run test:security
```

## 📝 **Pull Request Process**

### **Before Submitting**
1. **Create an issue** first to discuss major changes
2. **Fork the repository** and create a feature branch
3. **Write comprehensive tests** for new functionality
4. **Update documentation** as needed
5. **Run security checks** and ensure all tests pass

### **PR Checklist**
- [ ] Code follows security best practices
- [ ] All tests pass (`npm test`)
- [ ] Security tests included for new features
- [ ] Documentation updated (README, SECURITY.md)
- [ ] No sensitive data exposed in logs or APIs
- [ ] Proper error handling implemented
- [ ] Database changes include proper migrations

### **PR Template**
```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Security improvement
- [ ] Documentation update

## Security Considerations
- [ ] No sensitive data exposed
- [ ] Proper input validation
- [ ] Secure error handling
- [ ] Database security maintained

## Testing
- [ ] Unit tests added/updated
- [ ] Security tests included
- [ ] Manual testing completed
- [ ] Edge cases covered

## Checklist
- [ ] Self-review completed
- [ ] Tests pass locally
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
```

## 🐛 **Bug Reports**

### **Security Vulnerabilities**
**DO NOT** open public issues for security vulnerabilities. Instead:
1. Email security@yourproject.com with details
2. Include steps to reproduce
3. Provide potential impact assessment
4. Allow time for responsible disclosure

### **Bug Report Template**
```markdown
## Bug Description
Clear description of the bug and its impact.

## Reproduction Steps
1. Step one
2. Step two
3. Step three

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- Plugin version:
- Better Auth version:
- Node.js version:
- Database type and version:

## Security Impact
- [ ] No security impact
- [ ] Low security impact
- [ ] Medium security impact
- [ ] High security impact (email security team instead)
```

## 💡 **Feature Requests**

### **Feature Request Template**
```markdown
## Feature Description
Clear description of the proposed feature.

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
How should this feature work?

## Alternatives Considered
What other solutions were considered?

## Security Considerations
How does this feature impact security?

## PCI DSS Compliance
How does this feature support PCI DSS requirements?
```

## 📚 **Documentation Guidelines**

### **Code Documentation**
```typescript
/**
 * Validates that a new password doesn't match recent password history
 * @param password - The new password to validate (never logged)
 * @param userId - The user ID for history lookup
 * @param options - Configuration options for validation
 * @throws {Error} When password matches recent history
 * @security Implements PCI DSS 8.2.3 password history requirement
 */
async function validatePasswordHistory(
  password: string,
  userId: string,
  options: PCIDSSOptions
): Promise<void> {
  // Implementation
}
```

### **README Updates**
- Keep security architecture explanations current
- Update configuration examples
- Maintain migration guides
- Include performance considerations

### **Security Documentation**
- Document new security features in SECURITY.md
- Update threat model when applicable
- Maintain compliance mapping
- Include security testing procedures

## 🔄 **Release Process**

### **Version Numbering**
- **Major** (X.0.0): Breaking changes or major security updates
- **Minor** (0.X.0): New features, non-breaking changes
- **Patch** (0.0.X): Bug fixes, security patches

### **Release Checklist**
- [ ] All tests pass
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Migration guides provided (if needed)
- [ ] Changelog updated
- [ ] Version number bumped
- [ ] Git tag created

## 🏆 **Recognition**

Contributors who make significant improvements to security, compliance, or functionality will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

## 📞 **Getting Help**

- **General questions**: Open a GitHub issue
- **Security concerns**: Email security team
- **Development help**: Join our Discord/Slack channel
- **Documentation issues**: Open a documentation PR

## 🔐 **Security Commitment**

This project takes security seriously. All contributors are expected to:
- Follow secure coding practices
- Report security issues responsibly
- Respect user privacy and data protection
- Maintain PCI DSS compliance standards

---

Thank you for contributing to Better Auth PCI DSS Plugin! Your efforts help make authentication more secure for everyone. 🚀 