-- Optional policies for S/4 systems can be used for extended system changelog and monitoring but need to be adjusted by the customer before activation. 
-- The usage of the policies needs to be evaluated carfully. E.g. audit all actions for the SYSTEM user is 
-- only necessary if there are specific compliance requirements.
-- These policies have the prefix '_SAPS4_Opt_'. They vary with the usage of the SAP HANA database and cannot be defined identical for all HANA systems.

-- technical users where we expect high frequent access should be excluded
-- replace following users with the actual SAPABAP user 
--     Database user <SAPABAP1> (e.g. SAPHANADB)
--     add to the same occurrences other technical users like 
--     SAPABAP1SHD (reduced downtime user for SUM)
--     SAPDBCTRL used by SAP Host Agent
--     or any other technical user you expect to execute many operations
--     on a regular base.
-- users must be added comma separated
-- the schema defined by <SAPABAP1>.* must be replaced by the actual DB schema of S4
-- While policies for specific audit actions could also be implemented in the System DB for a Tenant DB
-- by adding "FOR <TENANTDB>" to the create audit policy statement in the System DB
-- to prevent these from changes in the Tenant DB, these
-- policies are meant to be implemented directly in Tenant DB and/or System DB.
 
 
-- optional policy
-- needed for extended system changelog
-- Tenant and System DB
-- if XSC repository is used this policy might cause many entries in the audit log.
-- in a development system we expect this to happen very often so this policy might not be useful
CREATE AUDIT POLICY "_SAPS4_Opt_01 Repository" 
  AUDITING ALL
      ACTIVATE REPOSITORY CONTENT,
      EXPORT REPOSITORY CONTENT,
      IMPORT REPOSITORY CONTENT
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_01 Repository" ENABLE; 
 
  
-- optional policy
-- audit for DDL statements is only workload relevant
-- in case HANA is not exclusively used for S/4HANA the policy 
-- will cause a huge amount of not relevant entries
-- and a negative impact on performance is expected
-- exclude all users which you expect to execute DDL
-- Tenant and System DB
CREATE AUDIT POLICY "_SAPS4_Opt_02 Data Definition" 
  AUDITING SUCCESSFUL
      ALTER FULLTEXT INDEX,
      ALTER GEOCODE INDEX,
      ALTER STATISTICS,
      ALTER WORKLOAD CLASS,
      ALTER WORKLOAD MAPPING,
      CREATE FULLTEXT INDEX,
      CREATE GEOCODE INDEX,
      CREATE GRAPH WORKSPACE,
      CREATE SCHEMA,
      CREATE STATISTICS,
      CREATE WORKLOAD CLASS,
      CREATE WORKLOAD MAPPING,
      DROP FULLTEXT INDEX,
      DROP GEOCODE INDEX,
      DROP GRAPH WORKSPACE,
      DROP SCHEMA,
      DROP STATISTICS,
      DROP WORKLOAD CLASS,
      DROP WORKLOAD MAPPING,
      REFRESH STATISTICS,
-- Following actions might already be audited on the S4 Schema 
-- if the policy "_SAPS4_02 Schema Data Definition"  is implemented.
      CREATE TABLE,
      ALTER TABLE,
      DROP TABLE,
      RENAME TABLE,
      RENAME COLUMN,
      CREATE VIEW,
      ALTER VIEW,
      DROP VIEW,
      CREATE PROCEDURE,
      ALTER PROCEDURE,
      DROP PROCEDURE,
      CREATE FUNCTION,
      ALTER FUNCTION,
      DROP FUNCTION,
      CREATE INDEX,
      ALTER INDEX,
      DROP INDEX,
      RENAME INDEX,
      CREATE TRIGGER,
      DROP TRIGGER,
      CREATE SEQUENCE,
      ALTER SEQUENCE,
      DROP SEQUENCE,
--    Auditing Synonym is only supported with HANA 2.0 SPS04 Rev45+
      CREATE SYNONYM,
      DROP SYNONYM
-- end of duplicate audit actions by "_SAPS4_02 Schema Data Definition"
-- if you exclude (comment out) the Actions already captured by "_SAPS4_02 Schema Data Definition"
-- do not exclude the user <SAPABAP> in this policy "_SAPS4_Opt_02 Data Definition" here
  EXCEPT FOR <SAPABAP1>, <SAPABAP1>SHD
  LEVEL INFO TRAIL TYPE TABLE RETENTION 7;
ALTER AUDIT POLICY "_SAPS4_Opt_02 Data Definition" ENABLE; 


-- optional policy  - not recommnded for SAP S/4 HANA systems.
-- additional remark: user SYSTEM should be deactivated and not used for day by day activities
-- user DBADMIN should be deactivated (in case of HANA Cloud)
-- generally, all security and changelog relevant actions are
-- already captured by implementing the audit policies in this project
-- additional logged actions will be even e.g. simple select calls on 
-- public synonyms.
-- additional audit log entries for HANA internal processes can occur: 
-- please refer to https://me.sap.com/notes/3297190 
-- this policy will create a lot of additional mostly unuseful entries in the audit log
-- do not activate this policy unless you have a clear technical purpose for capturing
-- all actions.
-- the actions already audited by other policies will be duplicated unless user SYSTEM
-- is excluded from all other policies
-- to do this add "EXCEPT FOR SYSTEM" to all policies
-- Tenant and System DB
CREATE AUDIT POLICY "_SAPS4_Opt_03 System User" 
  AUDITING ALL
    ACTIONS
      FOR SYSTEM , DBADMIN
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_Opt_03 System User" ENABLE; 

  
-- optional policy
-- needed for extended system changelog
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAPS4_Opt_04 Encryption" 
  AUDITING ALL
      ACTIVATE KEY MANAGEMENT CONFIGURATION,
      ADD KEY MANAGEMENT CONFIGURATION,
      ALTER APPLICATION ENCRYPTION,
      ALTER APPLICATION ENCRYPTION ROOT KEY,
      ALTER BACKUP ENCRYPTION,
      ALTER BACKUP ENCRYPTION ROOT KEY,
      ALTER KEY MANAGEMENT CONFIGURATION,
      ALTER LOG ENCRYPTION,
      ALTER LOG ENCRYPTION ROOT KEY,
      ALTER PERSISTENCE ENCRYPTION,
      ALTER PERSISTENCE ENCRYPTION ROOT KEY,
      ALTER ROOT KEYS BACKUP PASSWORD,
      DROP KEY MANAGEMENT CONFIGURATION,
      ENCRYPTION CONFIG CONTROL,
      TENANT BACKUP ENCRYPTION,
      TENANT LOG ENCRYPTION,
      TENANT PERSISTENCE ENCRYPTION,
      TENANT ROOT KEYS BACKUP PASSWORD
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_04 Encryption" ENABLE; 


-- optional policy
-- needed for monitoring
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAPS4_Opt_05 Read Dump" 
  AUDITING ALL
    EXECUTE ON 
      SYS.FULL_SYSTEM_INFO_DUMP_RETRIEVE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_05 Read Dump" ENABLE; 


-- optional policy
-- needed for monitoring
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
-- unless it is used on a regular base e.g. by a technical user to retrieve tracefiles
CREATE AUDIT POLICY "_SAPS4_Opt_06 Read Trace" 
  AUDITING ALL
    SELECT ON 
      SYS.M_TRACEFILE_CONTENTS, 
      SYS_DATABASES.M_TRACEFILE_CONTENTS
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_06 Read Trace" ENABLE; 


-- optional policy
-- needed for monitoring
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAPS4_Opt_07 Management Console" 
  AUDITING ALL
    EXECUTE ON 
      SYS.MANAGEMENT_CONSOLE_PROC
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_07 Management Console" ENABLE; 
 
 
-- optional policy
-- needed for monitoring
-- Tenant DB
-- this policy should not cause many entries in the audit log
-- if HDI is not used.
-- in a development system where HDI is used this policy will cause
-- not relevant data in the audit log
CREATE AUDIT POLICY "_SAPS4_Opt_08 HDI" 
  AUDITING ALL
    EXECUTE ON 
      _SYS_DI.*
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_08 HDI" ENABLE; 

 
-- optional policy
-- needed for extended system changelog
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
-- unless database connections are created on a regular base by technical user
CREATE AUDIT POLICY "_SAPS4_Opt_09 Data Provisioning" 
  AUDITING ALL
      ALTER ADAPTER,
      ALTER AGENT,
      ALTER REMOTE SOURCE,
      ALTER REMOTE SUBSCRIPTION,
      CREATE ADAPTER,
      CREATE AGENT,
      CREATE AGENT GROUP,
      CREATE REMOTE SOURCE,
      CREATE REMOTE SUBSCRIPTION,
      DROP ADAPTER,
      DROP AGENT,
      DROP AGENT GROUP,
      DROP REMOTE SOURCE,
      DROP REMOTE SUBSCRIPTION,
      PROCESS REMOTE SUBSCRIPTION EXCEPTION
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_09 Data Provisioning" ENABLE; 
 
 
-- optional policy
-- needed for monitoring
-- Tenant and System DB
CREATE AUDIT POLICY "_SAPS4_Opt_10 Debugger"
  AUDITING ALL
      DEBUGGER ATTACH PROCESS,
      DEBUGGER EXECUTION
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_10 Debugger" ENABLE;


-- optional policy
-- needed for monitoring
-- Tenant and System DB
CREATE AUDIT POLICY "_SAPS4_Opt_11 Password Blocklist" 
  AUDITING SUCCESSFUL
    DELETE,
    INSERT,
    UPDATE
  ON _SYS_SECURITY._SYS_PASSWORD_BLACKLIST
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_Opt_11 Password Blocklist" ENABLE;


-- optional policy
-- needed for monitoring
-- In certain circumstances it might make sense to log successful connect attempts
-- but technical users connecting frequently should be excluded
-- Tenant and System DB
CREATE AUDIT POLICY "_SAPS4_Opt_12 session connect successful" 
  AUDITING SUCCESSFUL
    CONNECT
  EXCEPT FOR <SAPABAP1>
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAPS4_Opt_12 session connect successful" ENABLE;


-- optional policy
-- needed for extended system changelog
-- System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAPS4_Opt_13 TenantDB modifications" 
  AUDITING ALL
    ALTER DATABASE,
    CREATE DATABASE,
    DROP DATABASE,
    RENAME DATABASE,
    START DATABASE,
    STOP DATABASE
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_13 TenantDB modifications" ENABLE;
