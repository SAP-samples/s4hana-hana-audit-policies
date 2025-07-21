/** 
  ===============================================================
  ===== S/4HANA Audit Policies - Additional considerations ======
  ===============================================================
**/ 
/**
  The fourth called “additional” gives examples for policy definition for specific scenarios. 
  It is not recommended to apply the policies without careful consideration also they are not generally recommmended in SAP S/4HANA systems. 

  They are listed to give some ideas about additional possibilities, as in some cases, it might be useful to log access to specific objects or by specific user/user groups. 
**/

/**
  -----1. PREPARATIONS-------------------------
**/ 
/**
  There is no predefined naming etc. 
  Adoption cannot be done out of the box and the implementation is usually a huge effort, where knowledge of the database usage and objects is needed.
**/

/** 
  -----2. POLICIES-----------------------------
**/ 


/**
  --- Log access to a specific objects --- 
  Purpose: - 
  Details: 
    - This policy is only needed if there are special objects that needs additional protection. 
    - In case needed, do not create a policy for each single object you need to audit. Instead combine these objects to avoid a larger performance impact. 
    - Make sure to provide a meaningful name for this audit policy. 

**/ 
CREATE AUDIT POLICY "<access to specific objects>"
AUDITING ALL
    -- adjust actions to your needs (e.g. INSERT, UPDATE, DELETE,...) 
    INSERT,
    UPDATE,
    DELETE
    -- adjust the list of objects 
     ON <list of objects>
     -- adjust level and retention to your needs
  LEVEL INFO TRAIL TYPE TABLE RETENTION 20;  
ALTER AUDIT POLICY "<access to specific objects>" ENABLE;



/**
  --- Log access by users from a dedicated group (e.g. supporter) ---
  Purpose: - 
  Details: 
    - This policy is only needed in case all actions of dedicated users (e.g. support personnel) need to be audited. 
    - In such a case it is useful group these users in a specific user group.
    - In this policy more user groups can be added, by adding them to a comma separate list. 
    - In case you want to specifically exclude a user group (e.g. HDI technical user group) this can be done with the clause " EXCEPT FOR". 
    - Make sure to provide a meaningful name for this audit policy. 
**/ 
CREATE AUDIT POLICY "<usergroup name audit all>"
AUDITING ALL
    -- adjust the actions to your need 
    ACTIONS
    -- adjust the list of user groups to your need
     FOR PRINCIPALS USERGROUP <usergroup name>
  -- adjust level and retention to your needs 
  LEVEL INFO TRAIL TYPE TABLE RETENTION 20;  
ALTER AUDIT POLICY "<usergroup name audit all>" ENABLE;
