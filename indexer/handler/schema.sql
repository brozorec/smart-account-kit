-- Smart Account Indexer Database Schema (v0.7.0)
--
-- This schema defines:
-- 1. Indexes on the raw Goldsky table (smart_account_signer_events)
-- 2. Registry views for resolving signer/policy IDs to full data
-- 3. Live views for querying processed data (always fresh, no staleness)
--
-- The raw table `smart_account_signer_events` is created and managed by Goldsky.
-- We only add indexes and create views on top of it.
--
-- In v0.7.0, signers and policies have stable global registry IDs (u32).
-- Full signer/policy data lives in signer_registered/policy_registered events.
-- All other events reference by ID only.

-- ============================================================================
-- STEP 1: Create raw table (if Goldsky hasn't created it yet)
-- Goldsky will write into this table once the pipeline connects.
-- Column types match the Goldsky turbo/mirror pipeline output.
-- ============================================================================

CREATE TABLE IF NOT EXISTS smart_account_signer_events (
  id                TEXT PRIMARY KEY,
  ledger_sequence   BIGINT,
  ledger_closed_at  TIMESTAMPTZ,
  contract_id       TEXT,
  topics            TEXT,
  data              TEXT,
  event_type        TEXT,
  transaction_hash  TEXT
);

-- ============================================================================
-- STEP 2: Indexes on raw Goldsky table
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_events_contract
ON smart_account_signer_events(contract_id);

CREATE INDEX IF NOT EXISTS idx_events_type
ON smart_account_signer_events(event_type);

CREATE INDEX IF NOT EXISTS idx_events_contract_type
ON smart_account_signer_events(contract_id, event_type);

CREATE INDEX IF NOT EXISTS idx_events_ledger
ON smart_account_signer_events(ledger_sequence);

-- ============================================================================
-- STEP 3: Signer registry view
-- Maps signer_id -> full signer data from signer_registered events
-- ============================================================================

CREATE OR REPLACE VIEW signer_registry AS
SELECT
  e.contract_id,
  (e.topics::jsonb->1->>'u32')::int as signer_id,
  e.data::jsonb->'vec' as signer_vec,
  e.ledger_sequence
FROM smart_account_signer_events e
WHERE e.event_type = 'signer_registered';

-- ============================================================================
-- STEP 4: Policy registry view
-- Maps policy_id -> policy address from policy_registered events
-- ============================================================================

CREATE OR REPLACE VIEW policy_registry AS
SELECT
  e.contract_id,
  (e.topics::jsonb->1->>'u32')::int as policy_id,
  e.data::jsonb->>'address' as policy_address,
  e.ledger_sequence
FROM smart_account_signer_events e
WHERE e.event_type = 'policy_registered';

-- ============================================================================
-- STEP 5: Live view for processed signers
-- Extracts signer_id from signer_added/signer_removed events, then
-- JOINs to signer_registry to resolve full signer data
-- ============================================================================

CREATE OR REPLACE VIEW processed_signers AS
WITH signer_events AS (
  SELECT
    e.id,
    e.contract_id,
    e.ledger_sequence,
    e.transaction_hash,
    e.event_type,
    (e.topics::jsonb->1->>'u32')::int as context_rule_id,
    (e.data::jsonb->'vec'->0->>'u32')::int as signer_id
  FROM smart_account_signer_events e
  WHERE e.event_type IN ('signer_added', 'signer_removed')
)
SELECT
  se.id,
  se.contract_id,
  se.ledger_sequence,
  se.transaction_hash,
  se.event_type,
  se.context_rule_id,
  se.signer_id,
  sr.signer_vec->0->>'symbol' as signer_type,
  sr.signer_vec->1->>'address' as signer_address,
  sr.signer_vec->2->>'bytes' as raw_bytes,
  -- For External signers with passkeys (> 65 bytes), extract just credential_id
  -- For Delegated signers (32 bytes ed25519), keep as-is
  CASE
    WHEN LENGTH(sr.signer_vec->2->>'bytes') > 130
    THEN SUBSTRING(sr.signer_vec->2->>'bytes' FROM 131)  -- Skip first 65 bytes (130 hex chars)
    ELSE sr.signer_vec->2->>'bytes'
  END as credential_id
FROM signer_events se
LEFT JOIN signer_registry sr ON se.contract_id = sr.contract_id AND se.signer_id = sr.signer_id;

-- ============================================================================
-- STEP 6: Live view for processed policies
-- Extracts policy_id from policy_added/policy_removed events, then
-- JOINs to policy_registry to resolve policy address
-- ============================================================================

CREATE OR REPLACE VIEW processed_policies AS
WITH policy_events AS (
  SELECT
    e.id,
    e.contract_id,
    e.ledger_sequence,
    e.transaction_hash,
    e.event_type,
    (e.topics::jsonb->1->>'u32')::int as context_rule_id,
    (e.data::jsonb->'vec'->0->>'u32')::int as policy_id
  FROM smart_account_signer_events e
  WHERE e.event_type IN ('policy_added', 'policy_removed')
)
SELECT
  pe.id,
  pe.contract_id,
  pe.ledger_sequence,
  pe.transaction_hash,
  pe.event_type,
  pe.context_rule_id,
  pe.policy_id,
  pr.policy_address
FROM policy_events pe
LEFT JOIN policy_registry pr ON pe.contract_id = pr.contract_id AND pe.policy_id = pr.policy_id;

-- ============================================================================
-- STEP 7: Live view for contract summary
-- Pre-aggregated statistics per contract
-- ============================================================================

CREATE OR REPLACE VIEW contract_summary AS
SELECT
  contract_id,
  COUNT(DISTINCT context_rule_id) as context_rule_count,
  COUNT(*) FILTER (WHERE signer_type = 'External' AND event_type != 'signer_removed') as external_signer_count,
  COUNT(*) FILTER (WHERE signer_type = 'Delegated' AND event_type != 'signer_removed') as delegated_signer_count,
  MIN(ledger_sequence) as first_seen_ledger,
  MAX(ledger_sequence) as last_seen_ledger,
  array_agg(DISTINCT context_rule_id ORDER BY context_rule_id) as context_rule_ids
FROM processed_signers
GROUP BY contract_id;
