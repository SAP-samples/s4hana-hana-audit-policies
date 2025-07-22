
/** 
  ==========================================
  =====Optional S/4HANA Audit Policies======
  ==========================================
**/ 
/**
  The third set called "optional" suggests policy definition for extended changelog and monitoring. 
  These policies vary with the usage of the SAP HANA DB and cannot be defined identical for all systems.
  They can be used to monitor access to the S/4HANA Schema, but need to be adjusted before activation.
  The usage of the policies needs to be evaluated carefully e.g. audit all actions of the SYSTEM user is only needed,
  if there are specific compliance requirements. Some of the policies can produce a huge amount of log entries that are not relevant and
  could lead to a negative impact to performance. 
  Optional S/4HANA audit policies have the prefix '_SAPS4_Opt_'. 
**/
/** 
  -----1. PREPARATIONS-------------------------
**/ 
/**
  - Replace the placeholder <SAPABAP1> with the S/4HANA database user (e.g. SAPHANADB).
  - To avoid a big amount of meaningless audit log entries, exclude the following users from the policies by adding them to a comma-separated list within the "EXCEPT FOR" clause: 
    - technical users, where high frequent access is expected 
    - S/4HANA database user (actual SAPABAP user) 
    - <SAPABAP1>SHD user (technical shadow user, that is used during upgrade activities)
    - SAPDBCTRL user (technical user used by the SAP Host Agent) 
  
  The following policies are meant to be implemented directly on the Tenant DB and/or System DB. 
  Nevertheless specific audit actions can be implemented in the System DB for the Tenant DB. 
  To do so, the clause "FOR <TENANTDB>" must be added to the statement. 
**/
/**
/** 
  -----2. POLICIES-----------------------------
**/ 
 
/**
  --- Log changes for XSC repository in development systems ---
  Purpose: System changelog 
  Details: 
    - If an XSC repository is used this policy might cause many entries in the audit log. 
      Since this is very common in development systems, this policy might not be useful there. 
  Applicable for: Tenant DB and System DB
**/
  CREATE AUDIT POLICY "_SAPS4_Opt_01 Repository" 
  AUDITING ALL
      ACTIVATE REPOSITORY CONTENT,
      EXPORT REPOSITORY CONTENT,
      IMPORT REPOSITORY CONTENT
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_01 Repository" ENABLE; 
 
/**
  --- Log changes for data definitions (DDL) --- 
  Purpose: System changelog 
  Details: 
    - Audit for DDL statements is only workload relevant. 
    - In cases where the HANA DB is not exclusively used for S/4HANA, this policy will cause a huge amount of not relevant entries, 
      and negative impact on performance is expected. 
    - Exclude all users which you expect to execute DDL. Try to log only the "unexpected" actions. 
  Applicable for: Tenant DB and System DB
**/ 
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
-- Following actions might already be audited on the S4 Schema, if the policy "_SAPS4_02 Schema Data Definition"  is implemented.
-- Begin of duplicate audit actions by "2_s4hana_hana_audit_policy_recommended.sql - _SAPS4_02 Schema Data Definition"
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
-- End of duplicate audit actions by "_SAPS4_02 Schema Data Definition"
-- if you exclude (comment out) the actions already captured by "_SAPS4_02 Schema Data Definition", 
-- do not exclude the user <SAPABAP> in this policy "_SAPS4_Opt_02 Data Definition" here
  EXCEPT FOR <SAPABAP1>, <SAPABAP1>SHD
  LEVEL INFO TRAIL TYPE TABLE RETENTION 7;
ALTER AUDIT POLICY "_SAPS4_Opt_02 Data Definition" ENABLE; 

/**
  --- 
  Purpose: 
  Details: 
     - This policy is not recommended for SAP S/4HANA systems, as it will produce a lot or redundant audit log entries. 
     - Be very careful when using this policy and activate it only in case there is a clear technical purpose. 
        - All security and changelog relevant actions are already logged with the policies described in this project. This additional policy will also capture every other action executed by the SYSTEM user (e.g. select calls on public synonyms).   
        - The actions that are already audited by other policies will be duplicated unless the user SYSTEM is excluded from them. To do this add "EXCEPT FOR SYSTEM" to them. 
        - There might be additional audit log entries for HANA internal processes, please refer to https://me.sap.com/notes/3297190 to get more information. 
     - General recommendation: User SYSTEM should be deactivated an not used for day-by-day activities. 
  Applicable for: Tenant DB and System DB 
**/ 
CREATE AUDIT POLICY "_SAPS4_Opt_03 System User" 
  AUDITING ALL
    ACTIONS
      FOR SYSTEM
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_Opt_03 System User" ENABLE; 

/**
  --- Log changes of encryption settings --- 
  Purpose: System changelog
  Details: 
    - This policy should not cause many entries in the audit log. 
  Applicable for: Tenant DB and System DB 
**/ 
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

/**
  --- Log access to dumps --- 
  Purpose: Monitoring
  Details: 
    - This policy should not cause many entries in the audit log. 
  Applicable for: Tenant DB and System DB
**/
CREATE AUDIT POLICY "_SAPS4_Opt_05 Read Dump" 
  AUDITING ALL
    EXECUTE ON 
      SYS.FULL_SYSTEM_INFO_DUMP_RETRIEVE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_05 Read Dump" ENABLE; 

/**
  --- Log access to traces --- 
  Purpose: Monitoring
  Details: 
    - This policy should not cause many entries in the audit log, unless the trace is regularly used (e.g. by a technical user to retrieve the trace files).
  Applicable for: Tenant DB and System DB
**/ 
CREATE AUDIT POLICY "_SAPS4_Opt_06 Read Trace" 
  AUDITING ALL
    SELECT ON 
       -- this object only exists in SYSTEMDB, remove comment to enable:
       -- SYS_DATABASES.M_TRACEFILE_CONTENTS,
       SYS.M_TRACEFILE_CONTENTS
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_06 Read Trace" ENABLE; 

/**
  --- Log access to system management console --- 
  Purpose: Monitoring
  Details: 
    - This policy should not cause many entries in the audit log. 
  Applicable for: Tenant DB and System DB 
**/
CREATE AUDIT POLICY "_SAPS4_Opt_07 Management Console" 
  AUDITING ALL
    EXECUTE ON 
      SYS.MANAGEMENT_CONSOLE_PROC
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_07 Management Console" ENABLE; 
 
 /***
  --- Log activities on HDI --- 
  Purpose: System changelog 
  Details: 
    - In case the HDI Service is not enabled, the schema _SYS_DI might not exist in the tenant. 
    - If HDI is not used, this policy should not cause many entries. --> shouldn't there be none? 
    - In development systems where HDI is used, this policy will cause a lot of not relevant data in the audit log. Recommendation: Do not enable this policy in development systems. 
  Applicable for: Tenant DB 
 ***/
CREATE AUDIT POLICY "_SAPS4_Opt_08 HDI" 
  AUDITING ALL
    EXECUTE ON 
      _SYS_DI.*
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_08 HDI" ENABLE; 
 
/**
  --- Log changes of database connections for data provisioning --- 
  Purpose: System changelog
  Details: 
    - This policy should not cause many entries in the audit log, unless database connections are created on a regular basis by a technical user. 
  Applicable for: Tenant DB and System DB
**/
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
 
 /**
  --- Log usage of the debugger --- 
  Purpose: Monitoring
  Applicable for: Tenant DB and System DB
 **/ 
CREATE AUDIT POLICY "_SAPS4_Opt_10 Debugger"
  AUDITING ALL
      DEBUGGER ATTACH PROCESS,
      DEBUGGER EXECUTION
  LEVEL INFO TRAIL TYPE TABLE RETENTION 90;
ALTER AUDIT POLICY "_SAPS4_Opt_10 Debugger" ENABLE;

 /**
  --- Log changes of the password denylist --- 
  Purpose: System changelog
  Applicable for: Tenant DB and System DB
 **/ 
CREATE AUDIT POLICY "_SAPS4_Opt_11 Password Denylist" 
  AUDITING SUCCESSFUL
    DELETE,
    INSERT,
    UPDATE
  ON _SYS_SECURITY._SYS_PASSWORD_BLACKLIST
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_Opt_11 Password Denylist" ENABLE;

/**
  --- Log successful connect attempts ---
  Purpose: Monitoring
  Details: 
    - In certain circumstances, it might make sense to log successful connect attempts. To avoid a big amount of log data exclude technical users. 
  Applicable for: Tenant DB and System DB
**/
CREATE AUDIT POLICY "_SAPS4_Opt_12 session connect successful" 
  AUDITING SUCCESSFUL
    CONNECT
  EXCEPT FOR <SAPABAP1>
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAPS4_Opt_12 session connect successful" ENABLE;

/**
  --- Log changes from SystemDB to TenantDBs, e.g. stop of a TenantDB --- 
  Purpose: System changelog
  Details: 
    - This policy should not cause many entries in the audit log. 
  Applicable for: System DB
**/
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
