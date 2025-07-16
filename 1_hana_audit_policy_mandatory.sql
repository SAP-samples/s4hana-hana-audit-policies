/** 
  ==========================================
  =====Mandatory HANA Audit Policies========
  ==========================================
**/ 

/** 
  This is a first set of policies defined as mandatory to ensure traceability of security relevant changes.
  They are identical to the audit policies provided by "SAP HANA Cockpit Audit Policy Wizard" (starting with SAP HANA Cockpit 2.0 SP13). 
  These policies are set as defaults for HANA database tenant used by S/4HANA for new installations with SAP S/4HANA 2021 and SAP BW/4HANA 2021 and later. 
  For conversions and system copies, HANA audit policies are only enabled as defaults in case no other HANA audit policies are existing.
  
  Mandatory HANA audit policies have the prefix '_SAP_'. 
**/ 


/** 
  -----1. PREPARATIONS-------------------------
**/ 

/**
  While policies for specific audit actions could also be implemented in the System DB for a Tenant DB by adding "FOR <TENANTDB>" to the create audit policy statement in the System DB 
  to prevent these from changes in the Tenant DB, these policies are meant to be implemented directly in Tenant DB and/or System DB.
**/
-- enable audit in SystemDB:
ALTER SYSTEM ALTER CONFIGURATION ('nameserver.ini','SYSTEM') set ('auditing configuration','global_auditing_state' ) = 'true'  with reconfigure;
-- enable audit in TenantDB:
ALTER SYSTEM ALTER CONFIGURATION ('global.ini', 'system') set ('auditing configuration', 'global_auditing_state') = 'true'  with reconfigure;

/** 
There is a global setting for the minimal retention period. In case a shorter retention time is needed for a dedicated policy, the global minimum must be adjusted. The default value for the minimal retention period is 7 days.
**/ 
-- ALTER SYSTEM ALTER CONFIGURATION ('global.ini', 'system') set ('auditing configuration', 'minimal_retention_period') = '7'  with reconfigure;


/** 
  -----2. POLICIES-----------------------------
**/ 

/** 
  --- Log unsuccessful connect attempts --- 
  Purpose: Intrusion detection 
  Details: 
    - Many unsuccessful connect attempts may hint a brute force attack.
    - The result of the policy should be evaluated by an IDS (Intrusion Detection System)
  Applicable for: Tenant and System DB
**/
CREATE AUDIT POLICY "_SAP_session connect" 
  AUDITING UNSUCCESSFUL
    CONNECT
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAP_session connect" ENABLE;

/**
  --- Log all VALIDATE attempts ---
  Purpose: Intrusion detection 
  Details: 
    - Many VALIDATE attempts may hint a brute force attack.
    - The result of the policy should be evaluated by an IDS.  
  Applicable for: Tenant and System DB
**/ 
CREATE AUDIT POLICY "_SAP_session validate" 
  AUDITING ALL
    VALIDATE USER
  LEVEL ALERT TRAIL TYPE TABLE RETENTION 20;
ALTER AUDIT POLICY "_SAP_session validate" ENABLE;
  
/** 
  --- Log changes for authorization assignments ---
  Purpose: Security changelog 
  Details: 
    - In case an Identity Management system (IDM) system is used the IDM DB user should be excluded, otherwise the HANA and IDM systems changelogs contain redundant information.
  Applicable for: Tenant and System DB
**/ 
CREATE AUDIT POLICY "_SAP_authorizations" 
  AUDITING ALL
    GRANT ANY,
    REVOKE ANY
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_authorizations" ENABLE; 
 
 /**
  --- Log changes for roles, user groups and users --- 
  Purpose: Security changelog
  Details: 
    - In case an IDM system is used the IDM DB user should be excluded, otherwise the HANA and IDM systems changelogs contain redundant information.
    - In case HDI (HANA Deployment Infrastructure) is used exclude the _SYS_HDI user for the Dev and Q systems.
  Applicable for: Tenant and System DB
**/
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

/**
  --- Log changes for structured privileges in development systems. 
  Purpose: Security changelog
  Details: 
    - Since structured privileges are part of the development process, more entries for development systems are expected.
  Applicable for: Tenant and System DB
**/
CREATE AUDIT POLICY "_SAP_structured privileges" 
  AUDITING SUCCESSFUL
      ALTER STRUCTURED PRIVILEGE,
      CREATE STRUCTURED PRIVILEGE,
      DROP STRUCTURED PRIVILEGE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_structured privileges" ENABLE; 

/**
  --- Log changes for Personal Security Environments (PSE) and certificates --- 
  Purpose: System changelog
  Details: 
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/ 
CREATE AUDIT POLICY "_SAP_certificates" 
  AUDITING ALL
      ALTER PSE,
      CREATE CERTIFICATE,
      CREATE PSE,
      DROP CERTIFICATE,
      DROP PSE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_certificates" ENABLE; 
 
/**
  --- Log changes for authentication provider --- 
  Purpose: System changelog 
  Details: 
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/
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
 
/**
  --- Log changes for encryption setting --- 
  Purpose: System changelog
  Details:
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/
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
 
/**
  --- Log changes for _SYS_REPO authorizations in development systems --- 
  Purpose: System changelog
  Details: 
    - There are not many entries expected for this policy in the audit log.
    - In case an IDM system is used the IDM DB user should be excluded, otherwise the HANA and IDM systems changelogs contain redundant information.
    - If there is no development with HANA XSC, not many entries in the audit log are expected.  
  Applicable for: Tenant and System DB
**/
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

/**
  --- Log changes to system configuration --- 
  Purpose: System changelog 
  Details: 
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/
CREATE AUDIT POLICY "_SAP_configuration changes" 
  AUDITING ALL
    STOP SERVICE,
    SYSTEM CONFIGURATION CHANGE
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_configuration changes" ENABLE; 

/**
  --- Log changes for system licenses --- 
  Purpose: System changelog 
  Details: 
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/
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

/**
  --- Log backup and recovery activities ---
  Purpose: Monitoring
  Details: 
    - There are not many entries expected for this policy in the audit log.  
  Applicable for: Tenant and System DB
**/
CREATE AUDIT POLICY "_SAP_recover database" 
  AUDITING ALL
    BACKUP CATALOG DELETE,
      BACKUP DATA,
      RECOVER DATA
  LEVEL INFO TRAIL TYPE TABLE RETENTION 180;
ALTER AUDIT POLICY "_SAP_recover database" ENABLE; 
