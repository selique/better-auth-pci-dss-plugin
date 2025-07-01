// Jest setup file to handle ESM modules in CommonJS environment
let betterAuthTests;

beforeAll(async () => {
  try {
    // Dynamic import for ESM module
    console.log('Attempting to load @better-auth-kit/tests...');
    betterAuthTests = await import('@better-auth-kit/tests');
    console.log('Successfully loaded @better-auth-kit/tests');
    global.getTestInstance = betterAuthTests.getTestInstance;
    global.tryCatch = betterAuthTests.tryCatch;
  } catch (error) {
    console.warn('Warning: Failed to load @better-auth-kit/tests:', error.message);
    console.warn('Integration tests will be skipped');
    global.getTestInstance = null;
    global.tryCatch = null;
  }
}); 