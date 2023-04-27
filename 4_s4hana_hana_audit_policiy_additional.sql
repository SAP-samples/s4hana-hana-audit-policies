-- in some cases, it might be useful to log access to specific objects or for specific use cases.
-- following policies are just examples and need to be adjusted to your scenario
-- the policies here are not meant to be implemented in any case. They are to give you some
-- ideas about additional possibilities.
-- usually they are more effort to implement and need intimate knowledge of the database usage and objects.


-- additional possible policy
-- only needed it special objects should be protected
-- Do not create policies for every single object you need to audit. Combine the objects in 
-- as few as possible policies to avoid performance impact
-- give it a meaningful name
CREATE AUDIT POLICY "<access to specific objects>"
AUDITING ALL
-- e.g. ACTION: SELECT
    SELECT
     ON <list of objects>
     -- adjust level and retention to your needs
  LEVEL INFO TRAIL TYPE TABLE RETENTION 20;  
ALTER AUDIT POLICY "<access to specific objects>" ENABLE;


-- additional possible policy
-- in case all actions of e.g. support personal needs to be audited
-- then it is useful to create a specific usergroup for that kind of access
-- EXCEPT FOR PRINCIPAL USERGROUP <usergroup name> is also possible. E.g. if you want to exclude HDI technical usergroup
-- give it a meaningful name
CREATE AUDIT POLICY "<usergroup name audit all>"
AUDITING ALL
    ACTIONS
     FOR PRINCIPALS USERGROUP <usergroup name>
-- adjust level and retention to your needs
  LEVEL INFO TRAIL TYPE TABLE RETENTION 20;  
ALTER AUDIT POLICY "<usergroup name audit all>" ENABLE;
