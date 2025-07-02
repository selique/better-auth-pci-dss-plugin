# Contributing to Better Auth PCI DSS Plugin 🤝

Guidelines for contributing to the Better Auth PCI DSS Plugin.

## 🚀 **Quick Start**

### **Prerequisites**
- Node.js 18+ and npm
- Git
- Understanding of PCI DSS security requirements
- Familiarity with Better Auth framework

### **Setup**
```bash
git clone https://github.com/your-username/better-auth-pci-dss-plugin.git
cd better-auth-pci-dss-plugin
npm install
npm test
npm run lint
```

## 🔧 **Development Standards**

### **Security First**
- Never expose sensitive data in user-facing APIs
- Use PBKDF2-SHA512 for password hashing (Node.js crypto, better-auth compatible)
- Follow least privilege principle in database access
- Validate all inputs and sanitize outputs
- Log security events appropriately (without sensitive data)

### **Code Quality**
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
    if (await validatePassword(password, entry.passwordHash)) {
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
- Use dedicated tables for sensitive data
- Implement proper foreign key constraints
- Include cascade deletion for cleanup
- Add appropriate indexes for performance
- Never store plaintext passwords

## 🧪 **Testing Requirements**

### **Comprehensive Tests**
All contributions must include tests:

```typescript
describe('Password History Validation', () => {
  it('should reject password that matches history', async () => {
    const mockAdapter = createMockAdapter();
    const testPassword = 'TestPassword123!';
    
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
- Input validation tests for all user inputs
- SQL injection prevention verification
- Access control boundary testing
- Error handling security tests

### **Running Tests**
```bash
npm test                  # All tests
npm run test:coverage     # With coverage
npm run test:security     # Security-specific tests
```

## 📝 **Pull Request Process**

### **Before Submitting**
1. Create an issue first to discuss major changes
2. Fork the repository and create a feature branch
3. Write comprehensive tests for new functionality
4. Update documentation as needed
5. Run security checks and ensure all tests pass

### **PR Checklist**
- [ ] Code follows security best practices
- [ ] All tests pass (`npm test`)
- [ ] Security tests included for new features
- [ ] Documentation updated (README, SECURITY.md)
- [ ] No sensitive data exposed in logs or APIs
- [ ] Proper error handling implemented
- [ ] Database changes include proper setup scripts

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
- Database provider:
- Node.js version:
```

## 🔒 **Security Guidelines**

### **Code Security**
- Never log passwords or sensitive data
- Use parameterized queries to prevent SQL injection
- Implement proper error handling without information leakage
- Follow OWASP security guidelines
- Use secure random number generation

### **Database Security**
- Isolate sensitive data in dedicated tables
- Use proper foreign key constraints
- Implement cascade deletion
- Add appropriate indexes
- Never expose internal database structure

## 📚 **Documentation Standards**

### **Code Documentation**
```typescript
/**
 * Validates password against user's password history
 * @param password - The new password to validate
 * @param userId - The user's unique identifier
 * @param adapter - Database adapter for querying history
 * @throws Error if password matches recent history
 */
async function validatePasswordHistory(
  password: string,
  userId: string,
  adapter: DatabaseAdapter
): Promise<void> {
  // Implementation
}
```

### **README Updates**
- Keep examples current and working
- Include security considerations
- Update configuration options
- Maintain backward compatibility notes

## 🔄 **Release Process**

### **Version Numbering**
- **Major**: Breaking changes (e.g., 1.0.0 → 2.0.0)
- **Minor**: New features, backward compatible (e.g., 1.0.0 → 1.1.0)
- **Patch**: Bug fixes, backward compatible (e.g., 1.0.0 → 1.0.1)

### **Release Checklist**
- [ ] All tests passing
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Migration guide updated (if needed)
- [ ] Version bumped appropriately
- [ ] Changelog updated

## 🤝 **Community Guidelines**

### **Code of Conduct**
- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn and contribute
- Maintain professional communication

### **Getting Help**
- Check existing issues and documentation first
- Ask questions in GitHub discussions
- Provide context and examples when asking for help
- Share knowledge and help others

---

> **🔐 Security First**: All contributions must prioritize security. When in doubt, choose the more secure approach and document security considerations.

> **📋 Quality**: We value well-tested, documented code over quick fixes. Take time to do it right. 