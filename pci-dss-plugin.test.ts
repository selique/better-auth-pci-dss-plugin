import { pciDssPasswordPolicy } from "../index";
import { HookEndpointContext } from "better-auth";
import { InputContext } from "better-call";

// Mock do contexto do Better Auth para testes
// A estrutura real do InputContext do better-auth é mais complexa, mas para os testes
// vamos simular as propriedades que o plugin espera: user, db e input.
interface MockInputContext extends InputContext<any, any>, HookEndpointContext {
  user?: any; // Mock user object
  db?: any;   // Mock db object
  input?: {   // Mock input object, incluindo password
    password?: string;
  };
  json?: (data: any) => void; // Mock json response function para endpoints
  endpoint: { path: string }; // Adicionando a propriedade endpoint
}

const mockUser = {
  id: "user123",
  passwordHistory: [] as string[],
  lastPasswordChange: new Date().toISOString(),
  failedLoginAttempts: 0,
  accountLockedUntil: null as string | null,
  forcePasswordChange: false,
  lastLoginDate: new Date().toISOString(),
  isNewUser: false,
};

const mockDb = {
  updateUser: jest.fn(async (userId, data) => {
    Object.assign(mockUser, data);
    return mockUser;
  }),
  getUsers: jest.fn(async (query) => {
    // Simplified mock for getUsers for inactive accounts
    if (query.where && query.where.lastLoginDate && query.where.lastLoginDate.lt) {
      const cutoffDate = query.where.lastLoginDate.lt;
      if (mockUser.lastLoginDate < cutoffDate) {
        return [mockUser];
      }
    }
    return [];
  }),
};

const defaultOptions = {
  minLength: 12,
  minUppercase: 1,
  minLowercase: 1,
  minNumbers: 1,
  minSpecialChars: 1,
  passwordHistoryCount: 4,
  passwordChangeIntervalDays: 90,
  maxFailedLoginAttempts: 5,
  accountLockoutDurationMinutes: 30,
  inactiveAccountDeactivationDays: 90,
  forcePasswordChangeOnFirstLogin: true,
};

describe("PCI DSS Password Policy Plugin", () => {
  let plugin: ReturnType<typeof pciDssPasswordPolicy>;

  beforeEach(() => {
    plugin = pciDssPasswordPolicy(defaultOptions);
    // Reset mockUser before each test
    Object.assign(mockUser, {
      id: "user123",
      passwordHistory: [] as string[],
      lastPasswordChange: new Date().toISOString(),
      failedLoginAttempts: 0,
      accountLockedUntil: null,
      forcePasswordChange: false,
      lastLoginDate: new Date().toISOString(),
      isNewUser: false,
    });
    mockDb.updateUser.mockClear();
    mockDb.getUsers.mockClear();
  });

  // Testes para Comprimento Mínimo da Senha (3.1)
  describe("Minimum Password Length (3.1)", () => {
    it("should allow password meeting minimum length", async () => {
      const ctx: MockInputContext = { 
        input: { password: "StrongPassword1!" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).resolves.toBeUndefined();
    });

    it("should throw error for password shorter than minimum length", async () => {
      const ctx: MockInputContext = { 
        input: { password: "Short1!" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must be at least 12 characters long.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });
  });

  // Testes para Complexidade da Senha (3.2)
  describe("Password Complexity (3.2)", () => {
    it("should allow password meeting all complexity requirements", async () => {
      const ctx: MockInputContext = { 
        input: { password: "ComplexP@ssw0rd" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).resolves.toBeUndefined();
    });

    it("should throw error if missing uppercase", async () => {
      const ctx: MockInputContext = { 
        input: { password: "complexp@ssw0rd" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must contain at least one uppercase letter.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });

    it("should throw error if missing lowercase", async () => {
      const ctx: MockInputContext = { 
        input: { password: "COMPLEXP@SSW0RD" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must contain at least one lowercase letter.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });

    it("should throw error if missing number", async () => {
      const ctx: MockInputContext = { 
        input: { password: "ComplexP@ssword" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must contain at least one number.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });

    it("should throw error if missing special character", async () => {
      const ctx: MockInputContext = { 
        input: { password: "ComplexP4ssword" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must contain at least one special character (!@#$%^&*()).");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });
  });

  // Testes para Histórico de Senhas (3.4)
  describe("Password History (3.4)", () => {
    it("should throw error if new password is in history", async () => {
      mockUser.passwordHistory = ["OldPassword1!", "AnotherOld1!", "YetAnother1!"];
      const ctx: MockInputContext = { 
        input: { password: "OldPassword1!" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password cannot be one of the last 4 used passwords.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 1 });
    });

    it("should allow new password not in history", async () => {
      mockUser.passwordHistory = ["OldPassword1!", "AnotherOld1!", "YetAnother1!"];
      const ctx: MockInputContext = { 
        input: { password: "NewPassword1!" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).resolves.toBeUndefined();
    });

    it("should update password history on password change", async () => {
      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        input: { password: "NewPassword1!" }, 
        endpoint: { path: 
        '/auth/change-password' }, 
        method: 'POST', 
        path: '/auth/change-password', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await plugin.hooks!.after![1].handler(ctx);
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, expect.objectContaining({
        passwordHistory: ["NewPassword1!"],
        lastPasswordChange: expect.any(String),
        forcePasswordChange: false,
      }));
    });

    it("should keep history limited to passwordHistoryCount", async () => {
      mockUser.passwordHistory = ["P1", "P2", "P3", "P4", "P5"];
      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        input: { password: "NewPassword!" }, 
        endpoint: { path: 
        '/auth/change-password' }, 
        method: 'POST', 
        path: '/auth/change-password', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await plugin.hooks!.after![1].handler(ctx);
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, expect.objectContaining({
        passwordHistory: ["NewPassword!", "P1", "P2", "P3"],
      }));
    });
  });

  // Testes para Frequência de Troca de Senha (3.3)
  describe("Password Change Frequency (3.3)", () => {
    it("should force password change if interval exceeded", async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - (defaultOptions.passwordChangeIntervalDays + 1));
      mockUser.lastPasswordChange = oldDate.toISOString();

      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await plugin.hooks!.after![0].handler(ctx);
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { forcePasswordChange: true });
    });

    it("should not force password change if interval not exceeded", async () => {
      const recentDate = new Date();
      recentDate.setDate(recentDate.getDate() - (defaultOptions.passwordChangeIntervalDays - 1));
      mockUser.lastPasswordChange = recentDate.toISOString();

      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.after![0].handler(ctx)).resolves.toBeUndefined();
      expect(mockDb.updateUser).not.toHaveBeenCalledWith(mockUser.id, { forcePasswordChange: true });
    });
  });

  // Testes para Bloqueio de Conta por Tentativas Inválidas (3.5)
  describe("Account Lockout (3.5)", () => {
    it("should lock account after max failed attempts", async () => {
      mockUser.failedLoginAttempts = defaultOptions.maxFailedLoginAttempts - 1;
      const ctx: MockInputContext = { 
        input: { password: "InvalidPassword" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      // Simulate one more failed attempt due to invalid password (e.g., wrong password, not policy violation)
      // For simplicity, we'll make it fail due to policy violation to trigger the counter
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow("Password must be at least 12 characters long.");
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: defaultOptions.maxFailedLoginAttempts });

      // Now, try to authenticate again, which should trigger the lockout logic
      mockUser.failedLoginAttempts = defaultOptions.maxFailedLoginAttempts; // Set to max to trigger lockout
      const lockoutCtx: MockInputContext = { 
        input: { password: "AnyPassword" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(lockoutCtx)).rejects.toThrow(`Account locked for ${defaultOptions.accountLockoutDurationMinutes} minutes due to too many failed attempts.`);
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, expect.objectContaining({
        accountLockedUntil: expect.any(String),
        failedLoginAttempts: 0,
      }));
    });

    it("should prevent login if account is locked", async () => {
      const lockedUntil = new Date();
      lockedUntil.setMinutes(lockedUntil.getMinutes() + 10); // Lock for 10 minutes from now
      mockUser.accountLockedUntil = lockedUntil.toISOString();

      const ctx: MockInputContext = { 
        input: { password: "AnyPassword" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).rejects.toThrow(`Account locked until ${lockedUntil.toISOString()}.`);
    });

    it("should reset failed attempts on successful policy check", async () => {
      mockUser.failedLoginAttempts = 3;
      const ctx: MockInputContext = { 
        input: { password: "ValidPassword1!" }, 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await expect(plugin.hooks!.before![0].handler(ctx)).resolves.toBeUndefined();
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { failedLoginAttempts: 0 });
    });
  });

  // Testes para Tratamento de Contas Inativas (3.6)
  describe("Inactive Account Handling (3.6)", () => {
    it("should deactivate inactive accounts via endpoint", async () => {
      const oldLoginDate = new Date();
      oldLoginDate.setDate(oldLoginDate.getDate() - (defaultOptions.inactiveAccountDeactivationDays + 1));
      mockUser.lastLoginDate = oldLoginDate.toISOString();

      const ctx: MockInputContext = { 
        db: mockDb, 
        json: jest.fn(), 
        endpoint: { path: 
        '/pci-dss/deactivate-inactive-accounts' }, 
        method: 'POST', 
        path: '/pci-dss/deactivate-inactive-accounts', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      // Simulate a call to the endpoint
      // Access the handler directly from the plugin's endpoints object
      await plugin.endpoints!.deactivateInactiveAccounts.handler(ctx);

      expect(mockDb.getUsers).toHaveBeenCalledWith(expect.objectContaining({
        where: {
          lastLoginDate: { lt: expect.any(String) },
        },
      }));
      // In a real test, you'd check if the user was actually deactivated/marked inactive
      // For this mock, we check the console log and the return message
      expect(ctx.json).toHaveBeenCalledWith({ message: "Deactivated 1 inactive accounts." });
    });
  });

  // Testes para Requisitos para a Primeira Senha de Novos Usuários (3.7)
  describe("First-time User Password Requirements (3.7)", () => {
    it("should force password change for new users", async () => {
      mockUser.lastPasswordChange = null; // Simulate a new user without a password change date
      mockUser.isNewUser = true; // Explicitly mark as new user

      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await plugin.hooks!.after![0].handler(ctx);
      expect(mockDb.updateUser).toHaveBeenCalledWith(mockUser.id, { forcePasswordChange: true });
    });

    it("should not force password change for existing users", async () => {
      mockUser.lastPasswordChange = new Date().toISOString(); // Existing user
      mockUser.isNewUser = false;

      const ctx: MockInputContext = { 
        user: mockUser, 
        db: mockDb, 
        endpoint: { path: 
        '/auth/login' }, 
        method: 'POST', 
        path: '/auth/login', 
        body: {}, 
        query: {}, 
        params: {}, 
        headers: {}, 
        request: {}, 
        response: {}, 
        set: {}, 
        store: {}, 
        log: {}, 
        html: {}, 
        redirect: {}, 
        error: {}, 
        setHeader: jest.fn(), 
        getHeader: jest.fn(), 
        getCookie: jest.fn(), 
        getSignedCookie: jest.fn(), 
        setCookie: jest.fn(), 
        setSignedCookie: jest.fn(), 
        removeCookie: jest.fn(), 
        removeSignedCookie: jest.fn(), 
        status: jest.fn(), 
        send: jest.fn(), 
        file: jest.fn(), 
        stream: jest.fn(), 
        on: jest.fn(), 
        off: jest.fn(), 
        once: jest.fn(), 
        emit: jest.fn(), 
        pipe: jest.fn(), 
        req: {}, 
        res: {} 
      } as MockInputContext;
      await plugin.hooks!.after![0].handler(ctx);
      expect(mockDb.updateUser).not.toHaveBeenCalledWith(mockUser.id, { forcePasswordChange: true });
    });
  });
});


