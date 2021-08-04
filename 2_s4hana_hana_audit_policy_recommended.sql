-- Recommended" policies for S/4 systems can be used to monitor access to the S/4HANA Schema but need to be adjusted by the customer before activation. 
-- These have the prefix '_SAPS4_'. These policies vary with the usage of the SAP HANA database and cannot be defined identical for all HANA systems.

-- technical users where we expect high frequent access should be excluded
-- replace following users with the actual SAPABAP user 
--     Database user <SAPABAP1> (e.g. SAPHANADB)
--     add to the same occurrences other technical users like 
--     SAPABAP1SHD (reduced downtime user for SUM)
--     or any other technical user you expect to execute many operations
--     on a regular base.
--     users must be added comma separated
-- the schema defined by <SAPABAP1>.* must be replaced by the actual DB schema of S4
-- While policies for specific audit actions could also be implemented in the System DB for a Tenant DB
-- by adding "FOR <TENANTDB>" to the create audit policy statement in the System DB
-- to prevent these from changes in the Tenant DB, these
-- policies are meant to be implemented directly in Tenant DB and/or System DB.


-- monitoring of direct access to S4HANA data. 
-- only <SAPABAP1> or <SAPABAP1SHD> user should access 
-- frequently. These actions should be contained in
-- the application log.
-- Exclude other technical users in case
-- of e.g. SDA access to the schema.
-- Auditing SELECT as read access log if DPP relevant data
-- is accessed directly on the database.
-- recommended
-- Tenant DB holding the schema for S/4HANA 
-- this should lead to some entries for support user accessing the
-- <SAPABAP1> schema. Access via DBACOCKPIT transaction with DBACOCKPIT
-- user on HANA should also appear.
CREATE AUDIT POLICY "_SAPS4_01 Schema Access Log" 
  AUDITING SUCCESSFUL
    DELETE,
    EXECUTE,
    INSERT,
    SELECT,
    UPDATE
  ON <SAPABAP1>.*
  EXCEPT FOR <SAPABAP1>
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_01 Schema Access Log" ENABLE; 
