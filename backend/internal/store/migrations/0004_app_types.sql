-- The products of the Umbrella family were renamed (Umbrella Monitoring → Beacon, Inventory DB → Ledger,
-- Umbrella Flow → Current): stored applications get the new type IDs. The old IDs are still accepted by the API.
UPDATE applications SET type = 'beacon' WHERE type = 'umbrella-monitoring';
UPDATE applications SET type = 'ledger' WHERE type = 'inventory-db';
UPDATE applications SET type = 'current' WHERE type = 'umbrella-flow';
-- Applications that still carry the old product name as their name (the default when connecting) get the new one.
UPDATE applications SET name = 'Beacon' WHERE type = 'beacon' AND name = 'Umbrella Monitoring';
UPDATE applications SET name = 'Ledger' WHERE type = 'ledger' AND name = 'Inventory DB';
UPDATE applications SET name = 'Current' WHERE type = 'current' AND name = 'Umbrella Flow';
