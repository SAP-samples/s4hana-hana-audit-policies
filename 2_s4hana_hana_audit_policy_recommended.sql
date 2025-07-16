/** 
  ==========================================
  =====Recommended HANA Audit Policies======
  ==========================================
**/ 

/**
  The second set of policies define "recommended" policies for S/4 systems. 
  These policies vary with the usage of the SAP HANA DB and cannot be defined identical for all systems.
  They can be used to monitor access to the S/4HANA Schema, but need to be adjusted before activation. 

  Recommended HANA audit policies have the prefix '_SAPS4_'. 
**/

/** 
  -----1. PREPARATIONS-------------------------
**/ 

/**
  - Replace the placeholder <SAPABAP1> with the S/4HANA database user (e.g. SAPHANADB).
  - Replace the schema defined by <SAPABAP1>.* with the S/4HANA Schema in the Tenant DB. 

  - To avoid a big amount of meaningless audit log entries, exclude the following users from the policies by adding them to a comma-separated list within the "EXCEPT FOR" clause: 
    - technical users, where high frequent access is expected 
    - S/4HANA database user (actual SAP ABAP user) 
    - SAPABAP1SHD user (technical shadow user, that is used during upgrade activities)
    - SAPDBCTRL user (technical user used by the SAP Host Agent) 
  
  The following policies are meant to be implemented directly on the Tenant DB and/or System DB. 
  Nevertheless specific audit actions can be implemented in the System DB for the Tenant DB. 
  To do so, the clause "FOR <TENANTDB>" must be added to the statement. 
**/ 


/** 
  -----2. POLICIES-----------------------------
**/ 

/**
  --- Log direct access to S/4HANA data --- 
  Purpose: Data Protection and Privacy (DPP)
  Details: 
    - Only the <SAPABAP1> or the <SAPABAP1SHD> user are expected to execute DDL statements frequently. 
      - These logs are already contained in the application log and can be excluded from the policy.
    - Exclude also other technical users in case e.g. SAP Smart Data Access (SDA) is available 
    - Auditing the executed "SELECT" statement is an equivalent for an Read-Access-Log (RAL) in case DPP relevant data is accessed directly on the database. 
    - In case a support user accesses the <SAPABAP1> schema this policy will produce entries in the audit log. 
    - Access via the DBACOCKPIT transaction with the DBACOCKPIT user will also appear. 
  Applicable for: Tenant DB (holding the S4HANA schema)
**/

CREATE AUDIT POLICY "_SAPS4_01 Schema Access Log" 
  AUDITING SUCCESSFUL
    DELETE,
    EXECUTE,
    INSERT,
    SELECT,
    UPDATE
  -- replace <SAPABAP1>.* with the S/4HANA schema
  ON <SAPABAP1>.*
  -- replace <SAPABAP1> with the S/4HANA database user
  EXCEPT FOR <SAPABAP1>, <SAPABAP1>SHD
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_01 Schema Access Log" ENABLE; 



/**
  --- Log object changes on S/4HANA schema from outside S/4HANA Application ---
  Purpose: DPP
  Details:
    - This policy will log all executions of DDL statements on the S/4HANA schema. 
    - With SAP HANA 2.0 SPS07 it is possible to specify the schema for the DDL auditing statement (ON SCHEMA clause). 
      - This is especially useful in cases where the HANA DB is not used exclusively for S/4HANA. 
    - Only the <SAPABAP1> or the <SAPABAP1SHD> user are expected to execute DDL statements frequently.
      - These logs are already contained in the application log and can be excluded from the policy.
      - Do not exclude other technical users. 
    - This policy should lead to logs about mostly unsuccessful actions, but successful changes e.f. index or synonym might also occur. 
    - Changes done via the DBACOCKPIT transaction with the DBACOCKPIT user are also covered. 
    - In case the optional audit policy "_SAPS4_Opt_02 Data Definition" is enabled, without removing schema specific DDL actions it will lead to redundant entries. 
      - Recommendation: Keep this policy as is and remove the redundant actions in the optional audit policy  
  Applicable for: Tenant DB (holding the S4HANA schema)
**/
CREATE AUDIT POLICY "_SAPS4_02 Schema Data Definition" 
  AUDITING ALL
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
    CREATE SYNONYM,
    DROP SYNONYM,
    CREATE SCHEDULER JOB,
    ALTER SCHEDULER JOB,
    DROP SCHEDULER JOB
  -- replace <SAPABAP1>.* with the S/4HANA schema
  ON SCHEMA <SAPABAP1>.*
  -- replace <SAPABAP1> with the S/4HANA database user
    EXCEPT FOR <SAPABAP1>, <SAPABAP1>SHD
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAPS4_02 Schema Data Definition" ENABLE; 
