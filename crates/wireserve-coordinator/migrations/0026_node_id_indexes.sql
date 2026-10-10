-- Every poll reads and rewrites its own node's rows by `node_id`, and with no
-- index each of those was a scan of the whole table: a poll's time under the
-- database lock grew with the number of services (and TLS reports) in the
-- mesh. Also what `ON DELETE CASCADE` from `nodes` looks the rows up by.
CREATE INDEX services_node_id ON services (node_id);
CREATE INDEX tls_ready_node_id ON tls_ready (node_id);
