-- A schema kept as a plain .sql file rather than inside a Kotlin migration. G-DM6 reads these
-- too, or the rule would hold only for the route the schema happens to take today.
CREATE TABLE dm_message_shadow (
  message_id BLOB PRIMARY KEY NOT NULL,
  body_env   BLOB NOT NULL
) WITHOUT ROWID;

CREATE VIRTUAL TABLE dm_message_search USING rtree(message_id, lo, hi);
