// This file augments the 'better-call' module to add better-auth specific context.

// Define placeholder interfaces to avoid top-level imports in an augmentation file.
// The actual types will be provided by the 'better-auth' package at compile time.
interface BetterAuthUser {
    id: string;
    [key: string]: any;
}

interface BetterAuthSession {
    id: string;
    [key: string]: any;
}


declare module 'better-call' {
    // Augment the existing InputContext interface from 'better-call'
    interface InputContext<TBody = unknown, TQuery = unknown> {
        user?: BetterAuthUser;
        session?: BetterAuthSession;
        db?: any; // The DB adapter provided by better-auth
        input?: {
            password?: string;
            [key: string]: any;
        };
    }
} 