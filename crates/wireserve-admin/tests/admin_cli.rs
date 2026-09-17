//! Integration tests against a real (mock) HTTP server — see
//! `tests/common/mod.rs`. These exercise the actual network-facing paths,
//! complementing the pure unit tests in `src/export_config.rs` and
//! `src/config.rs`.

mod common;

use common::MockCoordinator;
use wireserve_admin::client::AdminClient;
use wireserve_types::{NodeKind, PeerInfo};

const TOKEN: &str = "test-admin-token";

#[test]
fn export_config_end_to_end_and_private_key_never_leaves_process() {
    let mock = MockCoordinator::start(TOKEN);
    mock.set_peers(vec![PeerInfo {
        name: "homeserver".into(),
        pubkey: "existingpeerpubkey".into(),
        ip4: "100.90.0.3".into(),
        ip6: "fd00:90::3".into(),
        endpoint_addr: Some("duckdns.example.com:51820".into()),
        last_handshake: None,
    }]);

    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);
    // The mock coordinator serves both the admin routes and /register from
    // the same router (unlike the real coordinator, which binds them on
    // two separate listeners — see PLAN.md decisions log), so the same
    // base URL is valid for both parameters here.
    let conf = wireserve_admin::export_config::run(&client, mock.base_url.as_str(), "phone").unwrap();

    assert!(conf.contains("[Interface]"));
    assert!(conf.contains("[Peer]"));
    assert!(conf.contains("existingpeerpubkey"));
    assert!(conf.contains("AllowedIPs = 100.90.0.3/32, fd00:90::3/128"));
    assert!(conf.contains("Endpoint = duckdns.example.com:51820"));

    // create-node, register, list-peers — exactly three requests, no more.
    assert_eq!(mock.request_count(), 3);

    let private_key = conf
        .lines()
        .find(|l| l.starts_with("PrivateKey = "))
        .unwrap()
        .trim_start_matches("PrivateKey = ")
        .trim()
        .to_string();
    for body in mock.bodies() {
        assert!(
            !body.contains(&private_key),
            "private key leaked into a request body sent to the coordinator: {body}"
        );
    }
}

#[test]
fn invalid_name_makes_zero_network_calls_for_every_name_taking_command() {
    let mock = MockCoordinator::start(TOKEN);
    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);

    assert!(wireserve_admin::cmd_create_node(&client, "Bad_Name", NodeKind::Agent).is_err());
    assert!(wireserve_admin::cmd_revoke(&client, "Bad_Name").is_err());
    assert!(wireserve_admin::cmd_rejoin(&client, "Bad_Name").is_err());
    assert!(wireserve_admin::cmd_delete_node(&client, "Bad_Name").is_err());
    assert!(wireserve_admin::cmd_clear_endpoint(&client, "Bad_Name").is_err());
    assert!(wireserve_admin::cmd_export_config(&client, mock.base_url.as_str(), "Bad_Name").is_err());

    assert_eq!(
        mock.request_count(),
        0,
        "an invalid name must never reach the network"
    );
}

#[test]
fn clear_endpoint_hits_the_endpoint_subpath_not_the_node_path() {
    // The two DELETEs differ by one path segment and mean very different
    // things: /admin/nodes/{name} destroys the node record,
    // /admin/nodes/{name}/endpoint only drops a routing hint. Pin which
    // one the client actually calls.
    let mock = MockCoordinator::start(TOKEN);
    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);

    wireserve_admin::cmd_clear_endpoint(&client, "homeserver").unwrap();

    assert_eq!(mock.request_count(), 1);
    let paths = mock.paths();
    assert_eq!(paths, vec!["/admin/nodes/:name/endpoint".to_string()]);
}

#[test]
fn create_node_sends_admin_bearer_token_and_reaches_server() {
    let mock = MockCoordinator::start(TOKEN);
    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);

    let resp = wireserve_admin::cmd_create_node(&client, "homeserver", NodeKind::Agent).unwrap();
    assert_eq!(resp.name, "homeserver");
    assert_eq!(mock.request_count(), 1);
}

#[test]
fn wrong_admin_token_is_rejected_by_server() {
    let mock = MockCoordinator::start(TOKEN);
    let client = AdminClient::new(mock.base_url.as_str(), "wrong-token");

    let err = wireserve_admin::cmd_create_node(&client, "homeserver", NodeKind::Agent);
    assert!(err.is_err());
}

// ---- Regression coverage: admin and node-facing listeners are separate ----
//
// The real coordinator binds /admin/* and /register on two independently
// configured listeners (spec §4.0). export_config::run must use its
// register_url parameter for /register and never fall back to the admin
// client's base URL for it — these two tests pin that down against mock
// servers that only serve one half each, the way the real deployment does.

#[test]
fn export_config_succeeds_against_two_genuinely_separate_listeners() {
    let admin_mock = MockCoordinator::start_admin_only(TOKEN);
    let register_mock = MockCoordinator::start_register_only(TOKEN);
    let client = AdminClient::new(admin_mock.base_url.as_str(), TOKEN);

    let conf = wireserve_admin::export_config::run(&client, register_mock.base_url.as_str(), "phone")
        .expect("export-config must work when admin and register URLs point at different listeners");
    assert!(conf.contains("[Interface]"));
}

#[test]
fn export_config_fails_cleanly_if_register_url_points_at_the_admin_only_listener() {
    let admin_mock = MockCoordinator::start_admin_only(TOKEN);
    let client = AdminClient::new(admin_mock.base_url.as_str(), TOKEN);

    // Pointing register_url at a listener with no /register route must be
    // a clean error, not a panic and not a silently-wrong success.
    let result = wireserve_admin::export_config::run(&client, admin_mock.base_url.as_str(), "phone");
    assert!(result.is_err());
}

#[test]
fn list_peers_reflects_mock_directory() {
    let mock = MockCoordinator::start(TOKEN);
    mock.set_peers(vec![PeerInfo {
        name: "homeserver".into(),
        pubkey: "pk".into(),
        ip4: "100.90.0.3".into(),
        ip6: "fd00:90::3".into(),
        endpoint_addr: None,
        last_handshake: None,
    }]);
    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);
    let resp = wireserve_admin::cmd_list_peers(&client).unwrap();
    assert_eq!(resp.peers.len(), 1);
    assert_eq!(resp.peers[0].name, "homeserver");
}

// ---- F8: delete-node ----

#[test]
fn delete_node_sends_delete_with_admin_token_and_validates_name_first() {
    let mock = MockCoordinator::start(TOKEN);
    let client = AdminClient::new(mock.base_url.as_str(), TOKEN);

    assert!(wireserve_admin::cmd_delete_node(&client, "Bad_Name").is_err());
    assert_eq!(mock.request_count(), 0);

    wireserve_admin::cmd_delete_node(&client, "orphan").unwrap();
    assert_eq!(mock.request_count(), 1);

    let wrong = AdminClient::new(mock.base_url.as_str(), "wrong-token");
    assert!(wireserve_admin::cmd_delete_node(&wrong, "orphan").is_err());
}
