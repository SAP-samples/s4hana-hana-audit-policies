-- Mandatory HANA audit policies have the prefix '_SAP_'. They are identical to the HANA audit policies recommended by
-- "SAP HANA Cockpit Audit Policy Wizard" (starting with SAP HANA Cockpit 2.0 SP13).

-- technical users where we expect high frequent access should be excluded
-- replace following users with the actual SAPABAP user 
--     Database user <SAPABAP1> (e.g. SAPHANADB)
--     add to the same occurrences other technical users like 
--     SAPABAP1SHD (reduced downtime user for SUM)
--     SAPDBCTRL used by SAP Host Agent
--     or any other technical user you expect to execute many operations
--     on a regular base.
--     users must be added comma separated
-- the schema defined by <SAPABAP1>.* must be replaced by the actual DB schema of S4
-- While policies for specific audit actions could also be implemented in the System DB for a Tenant DB
-- by adding "FOR <TENANTDB>" to the create audit policy statement in the System DB
-- to prevent these from changes in the Tenant DB, these
-- policies are meant to be implemented directly in Tenant DB and/or System DB.

-- enable audit in SystemDB:
ALTER SYSTEM ALTER CONFIGURATION ('nameserver.ini','SYSTEM') set ('auditing configuration','global_auditing_state' ) = 'true'  with reconfigure;
-- enable audit in TenantDB:
ALTER SYSTEM ALTER CONFIGURATION ('global.ini', 'system') set ('auditing configuration', 'global_auditing_state') = 'true'  with reconfigure;

-- make sure the minimal retention period does not prevent the creation of the audit policies
-- Some proposed audit policies are created with a minimal retention period of 7 days. 
-- either adjust the retention period of the audit policies
-- or decrease the global minimal retention period limit
-- ALTER SYSTEM ALTER CONFIGURATION ('global.ini', 'system') set ('auditing configuration', 'minimal_retention_period') = '7'  with reconfigure;


-- many unsuccessful connect attempts may hint a brute force attack.
-- the result of the policy should be evaluated by an IDS
-- mandatory
-- Tenant and System DB
CREATE AUDIT POLICY "_SAP_session connect" 
  AUDITING UNSUCCESSFUL
    CONNECT
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAP_session connect" ENABLE;


-- many VALIDATE attempts may hint a brute force attack.
-- the result of the policy should be evaluated by an IDS  
-- mandatory
-- Tenant and System DB
CREATE AUDIT POLICY "_SAP_session validate" 
  AUDITING ALL
    VALIDATE USER
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAP_session validate" ENABLE;

  
-- needed for security changelog
-- mandatory
-- Tenant and System DB
-- in case an Identity Management system (IDM) system is used the IDM DB user should be excluded
-- otherwise the HANA and IDM systems changelogs contain redundant information
CREATE AUDIT POLICY "_SAP_authorizations" 
  AUDITING ALL
    GRANT ANY,
    REVOKE ANY
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_authorizations" ENABLE; 
 
 
-- needed for security changelog 
-- mandatory
-- Tenant and System DB
-- in case of IDM system, the IDM user should be excluded
-- in case HDI is used exclude the _SYS_HDI user for the Dev and Q systems
CREATE AUDIT POLICY "_SAP_user administration" 
  AUDITING SUCCESSFUL
      ALTER ROLE,
      ALTER USER,
      ALTER USERGROUP,
      CREATE ROLE,
      CREATE USER,
      CREATE USERGROUP,
      DROP ROLE,
      DROP USER,
      DROP USERGROUP
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_user administration" ENABLE; 


-- needed for security changelog 
-- mandatory
-- Tenant and System DB
-- structured privileges are part of development process
-- hence, we expect more entries for development systems
CREATE AUDIT POLICY "_SAP_structured privileges" 
  AUDITING SUCCESSFUL
      ALTER STRUCTURED PRIVILEGE,
      CREATE STRUCTURED PRIVILEGE,
      DROP STRUCTURED PRIVILEGE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_structured privileges" ENABLE; 
 
 
-- needed for security changelog
-- mandatory
-- Tenant and System DB
-- we do not expect many entries in the audit log for this policy
CREATE AUDIT POLICY "_SAP_certificates" 
  AUDITING ALL
      ALTER PSE,
      CREATE CERTIFICATE,
      CREATE PSE,
      DROP CERTIFICATE,
      DROP PSE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_certificates" ENABLE; 
 
  
-- needed for security changelog
-- mandatory
-- Tenant and System DB
-- we do not expect many entries in the audit log for this policy
CREATE AUDIT POLICY "_SAP_authentication provider" 
  AUDITING ALL
      ALTER JWT PROVIDER,
      ALTER LDAP PROVIDER,
      ALTER SAML PROVIDER,
      CREATE JWT PROVIDER,
      CREATE LDAP PROVIDER,
      CREATE SAML PROVIDER,
      DROP JWT PROVIDER,
      DROP LDAP PROVIDER,
      DROP SAML PROVIDER,
      VALIDATE LDAP PROVIDER
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_authentication provider" ENABLE; 
 
 
-- needed for security changelog
-- mandatory
-- Tenant and System DB
-- we do not expect many entries in the audit log for this policy
CREATE AUDIT POLICY "_SAP_clientside encryption" 
  AUDITING ALL
      ALTER CLIENTSIDE ENCRYPTION COLUMN KEY,
      ALTER CLIENTSIDE ENCRYPTION KEYPAIR,
      CREATE CLIENTSIDE ENCRYPTION COLUMN KEY,
      CREATE CLIENTSIDE ENCRYPTION KEYPAIR,
      DROP CLIENTSIDE ENCRYPTION COLUMN KEY,
      DROP CLIENTSIDE ENCRYPTION KEYPAIR
  LEVEL CRITICAL TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_clientside encryption" ENABLE; 
 

-- needed for security changelog
-- mandatory
-- Tenant and System DB
-- exclude IDM user
-- without development with HANA XSC we do not expect many entries
CREATE AUDIT POLICY "_SAP_designtime privileges" 
  AUDITING SUCCESSFUL
    EXECUTE ON
      "_SYS_REPO"."GRANT_ACTIVATED_ANALYTICAL_PRIVILEGE",
      "_SYS_REPO"."GRANT_ACTIVATED_ROLE",
      "_SYS_REPO"."GRANT_APPLICATION_PRIVILEGE",
      "_SYS_REPO"."GRANT_PRIVILEGE_ON_ACTIVATED_CONTENT",
      "_SYS_REPO"."GRANT_SCHEMA_PRIVILEGE_ON_ACTIVATED_CONTENT",
      "_SYS_REPO"."REVOKE_ACTIVATED_ANALYTICAL_PRIVILEGE",
      "_SYS_REPO"."REVOKE_ACTIVATED_ROLE",
      "_SYS_REPO"."REVOKE_APPLICATION_PRIVILEGE",
      "_SYS_REPO"."REVOKE_PRIVILEGE_ON_ACTIVATED_CONTENT",
      "_SYS_REPO"."REVOKE_SCHEMA_PRIVILEGE_ON_ACTIVATED_CONTENT"
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_designtime privileges" ENABLE; 

-- needed for system changelog
-- mandatory
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAP_configuration changes" 
  AUDITING ALL
    STOP SERVICE,
    SYSTEM CONFIGURATION CHANGE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_configuration changes" ENABLE; 

-- needed for system changelog
-- mandatory
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAP_license addition" 
  AUDITING ALL
      SET SYSTEM LICENSE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_license addition" ENABLE; 

CREATE AUDIT POLICY "_SAP_license deletion" 
  AUDITING ALL
      UNSET SYSTEM LICENSE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_license deletion" ENABLE; 

-- needed for system changelog
-- mandatory
-- Tenant and System DB
-- this policy should not cause many entries in the audit log
CREATE AUDIT POLICY "_SAP_recover database" 
  AUDITING ALL
    BACKUP CATALOG DELETE,
      BACKUP DATA,
      RECOVER DATA
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_recover database" ENABLE; 
