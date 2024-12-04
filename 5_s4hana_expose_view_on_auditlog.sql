-- To expose a restricted view on HANA AUDIT_LOG it is not sufficient to create a view if the consumer does not have the AUDIT READ privilege himself.
-- to solve that issue a table function on top of AUDIT_LOG needs to be created. This can be done by user SYSTEM or any user with privilege AUDIT READ.
-- if the privilege EXECUTE on that function is granted a user can call the table function: 
-- GRANT EXECUTE ON <table function> TO <consuming user>;

-- access table function has exactely the same syntax like access a table only () has to be added.
-- instead of *, single columns can be defined. A where close can be added.
-- SELECT *FROM <function identifier> ();

-- for a table function a table_type as return format needs to be created.
-- the definition here contains all columns of the original view AUDIT_LOG.

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

-- to create a function use following code example. in this case the table function is created by user SYSTEM
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
  -- in this example we expose the results of one of the audit policy definitions. the where clause can be adopted to the use case.
  FROM PUBLIC.AUDIT_LOG WHERE AUDIT_POLICY_NAME = '_SAPS4_01 Schema Access Log'';
END;











