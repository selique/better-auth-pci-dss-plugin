import { pciDssPasswordPolicy } from './index';

describe('PCI DSS Password Policy Plugin', () => {
  it('should create plugin with correct id', () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.id).toBe('pci-dss-password-policy');
  });

  it('should define required schema fields', () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.schema?.users?.fields).toBeDefined();
    
    const fields = plugin.schema!.users!.fields;
    expect(fields.passwordHistory).toEqual({ type: 'string', array: true, default: [] });
    expect(fields.lastPasswordChange).toEqual({ type: 'date', default: null });
    expect(fields.forcePasswordChange).toEqual({ type: 'boolean', default: false });
    expect(fields.lastLoginDate).toEqual({ type: 'date', default: null });
  });

  it('should have correct hook structure', () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.hooks?.before).toHaveLength(1);
    expect(plugin.hooks?.after).toHaveLength(2);
  });

  it('should accept different configuration options', () => {
    const plugin1 = pciDssPasswordPolicy({
      passwordHistoryCount: 5,
      passwordChangeIntervalDays: 60,
      inactiveAccountDeactivationDays: 30,
      forcePasswordChangeOnFirstLogin: false,
    });

    const plugin2 = pciDssPasswordPolicy({
      passwordHistoryCount: 10,
      passwordChangeIntervalDays: 180,
      inactiveAccountDeactivationDays: 365,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin1).toBeDefined();
    expect(plugin2).toBeDefined();
    expect(plugin1.id).toBe('pci-dss-password-policy');
    expect(plugin2.id).toBe('pci-dss-password-policy');
  });

  it('should have matcher functions for hooks', () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    const beforeHook = plugin.hooks?.before?.[0];
    const afterHook1 = plugin.hooks?.after?.[0];
    const afterHook2 = plugin.hooks?.after?.[1];

    expect(beforeHook?.matcher).toBeDefined();
    expect(afterHook1?.matcher).toBeDefined();
    expect(afterHook2?.matcher).toBeDefined();
  });

  it('should export plugin as a function', () => {
    expect(typeof pciDssPasswordPolicy).toBe('function');
  });
}); 