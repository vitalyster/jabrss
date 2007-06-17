ATTACH DATABASE "jabrss_res.db" AS res;

BEGIN;

DELETE FROM res.resource WHERE NOT EXISTS (SELECT 1 FROM user_resource WHERE user_resource.rid = resource.rid);

DELETE FROM res.resource_history WHERE NOT EXISTS (SELECT 1 FROM user_resource WHERE user_resource.rid = resource_history.rid);

DELETE FROM res.resource_data WHERE NOT EXISTS (SELECT 1 FROM user_resource WHERE user_resource.rid = resource_data.rid);

COMMIT;
