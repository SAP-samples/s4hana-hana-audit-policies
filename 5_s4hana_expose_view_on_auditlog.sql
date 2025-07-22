
/** 
  ===============================================================
  ===== S/4HANA Expose View on Auditlog =========================
  ===============================================================
**/ 
/**
    This file contains an example implementation of a table function. It is needed if a part of the HANA audit log should to be exposed to a user without granting select on all audit entries.
    The coding is meant for HANA 2.0. 
    It is not sufficient to expose a restricted view on HANA AUDIT_LOG to a customer with no AUDIT READ privilege. By using a table function the access problem can be solved. 
    The table function can be created by user SYSTEM or by any user with AUDIT READ privilege. With the SQL SECURITY mode DEFINER, it will be executed with the privileges of the creator. 
    The definition in this file contains all columns of the original AUDIT_LOG view. 
**/
CREATE TYPE AUDIT_EXPOSER_TABLE_TYPE AS TABLE   
("TIMESTAMP" LONGDATE CS_LONGDATE, 
"HOST" VARCHAR(64),
"PORT" INTEGER CS_INT, 
"SERVICE_NAME" VARCHAR(32), 
"CONNECTION_ID" INTEGER CS_INT, 
"CLIENT_HOST" NVARCHAR(256), 
"CLIENT_IP" VARCHAR(45),
"CLIENT_PID" BIGINT CS_FIXED,
"CLIENT_PORT" INTEGER CS_INT, 
"USER_NAME" NVARCHAR(256), 
"STATEMENT_USER_NAME" NVARCHAR(256), 
"APPLICATION_NAME" NVARCHAR(256),
"APPLICATION_USER_NAME" NVARCHAR(256), 
"XS_APPLICATION_USER_NAME" NVARCHAR(256), 
"AUDIT_POLICY_NAME" NVARCHAR(256),
"EVENT_STATUS" VARCHAR(32), 
"EVENT_LEVEL" VARCHAR(16), 
"EVENT_ACTION" VARCHAR(64), 
"SCHEMA_NAME" NVARCHAR(256), 
"OBJECT_NAME" NVARCHAR(256), 
"PRIVILEGE_NAME" NVARCHAR(256), 
"ROLE_SCHEMA_NAME" NVARCHAR(256),
"ROLE_NAME" NVARCHAR(256), 
"GRANTEE_SCHEMA_NAME" NVARCHAR(256),
"GRANTEE" NVARCHAR(256), 
"GRANTABLE" VARCHAR(16), 
"FILE_NAME" VARCHAR(256), 
"SECTION" VARCHAR(128), 
"KEY" NVARCHAR(2000), 
"PREV_VALUE" NVARCHAR(5000), 
"VALUE" NVARCHAR(5000), 
"STATEMENT_STRING" NCLOB MEMORY THRESHOLD 1000, 
"COMMENT" VARCHAR(5000),
"ORIGIN_DATABASE_NAME" NVARCHAR(256),
"ORIGIN_USER_NAME" NVARCHAR(256)); 
-- To create a function use following code example. In this case the table function is created by user SYSTEM
CREATE FUNCTION SYSTEM.<function identifier> ()
    RETURNS AUDIT_EXPOSER_TABLE_TYPE
    LANGUAGE SQLSCRIPT
    SQL SECURITY DEFINER AS
BEGIN
  RETURN
    SELECT
        "TIMESTAMP",
        "HOST",
        "PORT",
        "SERVICE_NAME",
        "CONNECTION_ID",
        "CLIENT_HOST",
        "CLIENT_IP",
        "CLIENT_PID",
        "CLIENT_PORT",
        "USER_NAME",
        "STATEMENT_USER_NAME",
        "APPLICATION_NAME",
        "APPLICATION_USER_NAME",
        "XS_APPLICATION_USER_NAME",
        "AUDIT_POLICY_NAME",
        "EVENT_STATUS",
        "EVENT_LEVEL",
        "EVENT_ACTION",
        "SCHEMA_NAME",
        "OBJECT_NAME",
        "PRIVILEGE_NAME",
        "ROLE_SCHEMA_NAME",
        "ROLE_NAME",
        "GRANTEE_SCHEMA_NAME",
        "GRANTEE",
        "GRANTABLE",
        "FILE_NAME",
        "SECTION",
        "KEY",
        "PREV_VALUE",
        "VALUE",
        "STATEMENT_STRING",
        "COMMENT",
        "ORIGIN_DATABASE_NAME",
        "ORIGIN_USER_NAME"
  -- In this example we expose the results of one of the audit policy definitions. The WHERE clause can be adopted to the use case.
  FROM PUBLIC.AUDIT_LOG WHERE AUDIT_POLICY_NAME = '_SAPS4_01 Schema Access Log';
END;
/**
    The privilege EXECUTE on the table function is required to be able to call it. 
**/ 
-- GRANT EXECUTE ON <schema>.<function identifier> TO <consuming user>;
/**
    Access to table function works similar to a table access except '()' needs to be added at the end of the statement.
    Instead of '*', single columns can be defined. Also a WHERE clause can be added to adjust to the use case.
**/ 
-- SELECT *FROM <schema>.<function identifier> ();
