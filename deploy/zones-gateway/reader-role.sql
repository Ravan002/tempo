-- Run as the owner of a dedicated single-Zone TIDX database after schema initialization.
-- The API role inherits no writer, owner, administrator or other-Zone role.
CREATE ROLE zone_indexer_reader LOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
REVOKE ALL ON SCHEMA public FROM zone_indexer_reader;
GRANT USAGE ON SCHEMA public TO zone_indexer_reader;
GRANT SELECT ON TABLE public.blocks, public.txs, public.logs, public.receipts TO zone_indexer_reader;
-- Configure the role's password through the infrastructure secret manager.
-- Keep this database single-Zone and grant no access to other Zone schemas/tables.
