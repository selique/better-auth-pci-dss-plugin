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

  it("should define required schema tables and fields", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.schema?.pciPasswordHistory?.fields).toBeDefined();
    expect(plugin.schema?.pciUserMetadata?.fields).toBeDefined();

    // Verificar tabela de histórico de senhas
    const passwordHistoryFields = plugin.schema!.pciPasswordHistory!.fields;
    expect(passwordHistoryFields.id).toEqual({
      type: "string",
      required: true,
    });
    expect(passwordHistoryFields.userId).toEqual({
      type: "string",
      required: true,
      references: {
        model: "user",
        field: "id",
        onDelete: "cascade",
      },
    });
    expect(passwordHistoryFields.passwordHash).toEqual({
      type: "string",
      required: true,
    });
    expect(passwordHistoryFields.createdAt).toEqual({
      type: "date",
      required: true,
    });

    // Verificar tabela de metadados do usuário
    const userMetadataFields = plugin.schema!.pciUserMetadata!.fields;
    expect(userMetadataFields.id).toEqual({ type: "string", required: true });
    expect(userMetadataFields.userId).toEqual({
      type: "string",
      required: true,
      unique: true,
      references: {
        model: "user",
        field: "id",
        onDelete: "cascade",
      },
    });
    expect(userMetadataFields.lastPasswordChange).toEqual({
      type: "date",
      default: null,
    });
    expect(userMetadataFields.forcePasswordChange).toEqual({
      type: "boolean",
      default: false,
    });
    expect(userMetadataFields.lastLoginDate).toEqual({
      type: "date",
      default: null,
    });
    expect(userMetadataFields.createdAt).toEqual({
      type: "date",
      required: true,
    });
    expect(userMetadataFields.updatedAt).toEqual({
      type: "date",
      required: true,
    });
  });

  it("should have correct hook structure", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    expect(plugin.hooks?.before).toHaveLength(1);
    expect(plugin.hooks?.after).toHaveLength(2);
  });

  it("should accept different configuration options", () => {
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
    expect(plugin1.id).toBe("pci-dss-password-policy");
    expect(plugin2.id).toBe("pci-dss-password-policy");
  });

  it("should have matcher functions for hooks", () => {
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

  it("should export plugin as a function", () => {
    expect(typeof pciDssPasswordPolicy).toBe("function");
  });

  it("should not expose sensitive data in user table", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    // Verificar que não há campos sensíveis na tabela user
    expect(plugin.schema?.users).toBeUndefined();
    expect(plugin.schema?.user).toBeUndefined();

    // Verificar que dados sensíveis estão em tabelas dedicadas
    expect(plugin.schema?.pciPasswordHistory).toBeDefined();
    expect(plugin.schema?.pciUserMetadata).toBeDefined();
  });

  it("should use proper foreign key constraints", () => {
    const plugin = pciDssPasswordPolicy({
      passwordHistoryCount: 3,
      passwordChangeIntervalDays: 90,
      inactiveAccountDeactivationDays: 90,
      forcePasswordChangeOnFirstLogin: true,
    });

    const passwordHistoryUserId =
      plugin.schema!.pciPasswordHistory!.fields.userId;
    const userMetadataUserId = plugin.schema!.pciUserMetadata!.fields.userId;

    // Verificar referências corretas
    expect(passwordHistoryUserId.references).toEqual({
      model: "user",
      field: "id",
      onDelete: "cascade",
    });

    expect(userMetadataUserId.references).toEqual({
      model: "user",
      field: "id",
      onDelete: "cascade",
    });
  });
}); 