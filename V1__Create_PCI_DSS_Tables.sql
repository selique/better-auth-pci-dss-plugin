-- ====================================================================
-- Better Auth PCI DSS Plugin - Database Migration
-- Version: 2.0+
-- Database: PostgreSQL (adapt for MySQL/SQLite as needed)
-- ====================================================================

-- ====================================================================
-- 1. PASSWORD HISTORY TABLE
-- Stores historical password hashes to prevent reuse
-- ====================================================================
CREATE TABLE IF NOT EXISTS "pciPasswordHistory" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "userId" UUID NOT NULL,
    "passwordHash" VARCHAR(255) NOT NULL,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Foreign key constraint to ensure referential integrity
    CONSTRAINT "fk_pci_password_history_user" 
        FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
);

-- Add table comment
COMMENT ON TABLE "pciPasswordHistory" IS 'Stores password history for PCI DSS compliance - prevents password reuse';
COMMENT ON COLUMN "pciPasswordHistory"."passwordHash" IS 'PBKDF2-SHA512 hash format (v2.0+): salt:iterations:hash';

-- ====================================================================
-- 2. USER METADATA TABLE
-- Tracks user security-related metadata
-- ====================================================================
CREATE TABLE IF NOT EXISTS "pciUserMetadata" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "userId" UUID UNIQUE NOT NULL,
    "lastPasswordChange" TIMESTAMP WITH TIME ZONE,
    "forcePasswordChange" BOOLEAN DEFAULT false,
    "lastLoginDate" TIMESTAMP WITH TIME ZONE,
    "createdAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "updatedAt" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Foreign key constraint
    CONSTRAINT "fk_pci_user_metadata_user" 
        FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
);

-- Add table comment
COMMENT ON TABLE "pciUserMetadata" IS 'User security metadata for PCI DSS compliance tracking';
COMMENT ON COLUMN "pciUserMetadata"."forcePasswordChange" IS 'Flag to force password change on next login';
COMMENT ON COLUMN "pciUserMetadata"."lastPasswordChange" IS 'Timestamp of last password change for interval enforcement';

-- ====================================================================
-- 3. AUDIT LOG TABLE (Optional - for security event tracking)
-- Enable this if auditTrail: true in plugin config
-- ====================================================================
CREATE TABLE IF NOT EXISTS "pciAuditLog" (
    "id" UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    "userId" UUID NOT NULL,
    "eventType" VARCHAR(100) NOT NULL,
    "timestamp" TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    "ipAddress" VARCHAR(45), -- Supports both IPv4 and IPv6
    "userAgent" TEXT,
    "metadata" TEXT, -- JSON metadata for event details
    
    -- Foreign key constraint
    CONSTRAINT "fk_pci_audit_log_user" 
        FOREIGN KEY ("userId") REFERENCES "user"("id") ON DELETE CASCADE
);

-- Add table comment
COMMENT ON TABLE "pciAuditLog" IS 'Security audit log for PCI DSS compliance - tracks security events';
COMMENT ON COLUMN "pciAuditLog"."eventType" IS 'Event types: PASSWORD_CHANGE, LOGIN_ATTEMPT, ACCOUNT_LOCKOUT, etc.';
COMMENT ON COLUMN "pciAuditLog"."metadata" IS 'JSON string with additional event context';

-- ====================================================================
-- 4. PERFORMANCE INDEXES
-- Critical for query performance with large user bases
-- ====================================================================

-- Password History Indexes
CREATE INDEX IF NOT EXISTS "idx_pci_password_history_user_created" 
    ON "pciPasswordHistory" ("userId", "createdAt" DESC);

CREATE INDEX IF NOT EXISTS "idx_pci_password_history_created" 
    ON "pciPasswordHistory" ("createdAt");

-- User Metadata Indexes
CREATE INDEX IF NOT EXISTS "idx_pci_user_metadata_user" 
    ON "pciUserMetadata" ("userId");

CREATE INDEX IF NOT EXISTS "idx_pci_user_metadata_last_password_change" 
    ON "pciUserMetadata" ("lastPasswordChange");

CREATE INDEX IF NOT EXISTS "idx_pci_user_metadata_force_change" 
    ON "pciUserMetadata" ("forcePasswordChange") 
    WHERE "forcePasswordChange" = true;

-- Audit Log Indexes (if using audit trail)
CREATE INDEX IF NOT EXISTS "idx_pci_audit_log_user_timestamp" 
    ON "pciAuditLog" ("userId", "timestamp" DESC);

CREATE INDEX IF NOT EXISTS "idx_pci_audit_log_event_timestamp" 
    ON "pciAuditLog" ("eventType", "timestamp" DESC);

CREATE INDEX IF NOT EXISTS "idx_pci_audit_log_timestamp" 
    ON "pciAuditLog" ("timestamp" DESC);

-- ====================================================================
-- 5. INITIAL DATA SETUP
-- Initialize metadata for existing users (if migrating existing system)
-- ====================================================================

-- Insert metadata records for existing users
-- This is safe with ON CONFLICT - won't duplicate data
INSERT INTO "pciUserMetadata" ("userId", "createdAt", "updatedAt")
SELECT 
    "id" as "userId",
    NOW() as "createdAt",
    NOW() as "updatedAt"
FROM "user"
ON CONFLICT ("userId") DO NOTHING;

-- ====================================================================
-- 6. CLEANUP PROCEDURES (Optional)
-- Functions for maintaining data retention policies
-- ====================================================================

-- Function to clean old password history (keep only required count)
CREATE OR REPLACE FUNCTION cleanup_password_history(
    p_user_id UUID,
    p_keep_count INTEGER DEFAULT 4
) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    WITH old_passwords AS (
        SELECT "id"
        FROM "pciPasswordHistory"
        WHERE "userId" = p_user_id
        ORDER BY "createdAt" DESC
        OFFSET p_keep_count
    )
    DELETE FROM "pciPasswordHistory"
    WHERE "id" IN (SELECT "id" FROM old_passwords);
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to clean old audit logs (data retention)
CREATE OR REPLACE FUNCTION cleanup_audit_logs(
    p_retention_days INTEGER DEFAULT 365
) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM "pciAuditLog"
    WHERE "timestamp" < NOW() - INTERVAL '1 day' * p_retention_days;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- ====================================================================
-- 7. VERIFICATION QUERIES
-- Run these after migration to verify setup
-- ====================================================================

-- Verify tables were created
-- SELECT table_name FROM information_schema.tables 
-- WHERE table_name LIKE 'pci%' ORDER BY table_name;

-- Verify indexes were created
-- SELECT indexname, tablename FROM pg_indexes 
-- WHERE indexname LIKE 'idx_pci%' ORDER BY tablename, indexname;

-- Check foreign key constraints
-- SELECT tc.constraint_name, tc.table_name, kcu.column_name, 
--        ccu.table_name AS foreign_table_name,
--        ccu.column_name AS foreign_column_name 
-- FROM information_schema.table_constraints AS tc 
-- JOIN information_schema.key_column_usage AS kcu
--   ON tc.constraint_name = kcu.constraint_name
--   AND tc.table_schema = kcu.table_schema
-- JOIN information_schema.constraint_column_usage AS ccu
--   ON ccu.constraint_name = tc.constraint_name
--   AND ccu.table_schema = tc.table_schema
-- WHERE tc.constraint_type = 'FOREIGN KEY' 
--   AND tc.table_name LIKE 'pci%';

-- ====================================================================
-- Migration Complete
-- 
-- Next Steps:
-- 1. Update your Better Auth configuration to include the plugin
-- 2. Test password change functionality
-- 3. Monitor security logs if audit trail is enabled
-- 4. Set up scheduled cleanup jobs for data retention
-- ==================================================================== 