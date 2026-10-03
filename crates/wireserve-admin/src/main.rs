use clap::{Parser, Subcommand};
use wireserve_admin::client::AdminClient;
use wireserve_admin::config;
use wireserve_types::term::{clean, columns};
use wireserve_types::NodeKind;

#[derive(Parser)]
#[command(name = "wireserve-admin", about = "Manages a WireServe mesh through its coordinator")]
struct Cli {
    /// The coordinator's admin URL [env: WIRESERVE_COORDINATOR_URL]
    #[arg(long, value_name = "URL", global = true, display_order = 100)]
    coordinator_url: Option<String>,
    /// The admin token [env: WIRESERVE_ADMIN_TOKEN]
    // Or written to ~/.config/wireserve-admin/admin_token.
    #[arg(long, value_name = "TOKEN", global = true, display_order = 100)]
    admin_token: Option<String>,
    /// The coordinator's URL as nodes reach it [env: WIRESERVE_REGISTER_URL]
    // The node-facing listener (where /register lives), bound apart from
    // the admin one (spec §4.0). Required by `device create|refresh`;
    // `node create|rejoin` use it to fill in the `wireserve install`
    // command they print. Or written to ~/.config/wireserve-admin/register_url.
    #[arg(long, value_name = "URL", global = true, display_order = 100)]
    register_url: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Add, remove and list nodes
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Approve and list services
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Allow nodes to relay traffic for others
    Transit {
        #[command(subcommand)]
        action: TransitAction,
    },
    /// WireGuard configs for devices without the agent, such as phones
    // Spec §9.
    Device {
        #[command(subcommand)]
        action: DeviceAction,
    },
    /// Group services; a service is in `default` until put in another
    // PLAN.md M36. A fresh mesh grants `default` to everyone.
    Group {
        #[command(subcommand)]
        action: GroupAction,
    },
    /// Who may reach which group
    Grant {
        #[command(subcommand)]
        action: GrantAction,
    },
    /// Tag nodes, so grants can name them
    // Only an admin sets tags — a node never tags itself.
    Tag {
        #[command(subcommand)]
        action: TagAction,
    },
    /// Who a device belongs to
    Owner {
        #[command(subcommand)]
        action: OwnerAction,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Create a node and print its join token
    // Spec §4.1.
    Create {
        /// The node's name
        name: String,
        /// `static` for a peer without the agent; prefer `device create`
        #[arg(long, default_value = "agent", value_parser = ["agent", "static"])]
        kind: String,
        /// Seconds the join token stays valid, 0 for no expiry
        // Without it, the coordinator's default (WIRESERVE_JOIN_TOKEN_TTL_SECS,
        // 30 minutes unless set).
        #[arg(long, value_name = "SECS")]
        ttl: Option<u64>,
        /// The agent instance it will run as, for the printed install command
        // Only needed for an additional instance beside another agent on
        // the same host. Never sent to the coordinator.
        #[arg(long)]
        instance: Option<String>,
    },
    /// Print a new join token for an existing node
    // Spec §4.5.
    Rejoin {
        /// The node's name
        name: String,
        /// Seconds the join token stays valid, 0 for no expiry
        #[arg(long, value_name = "SECS")]
        ttl: Option<u64>,
        /// The agent instance it runs as, for the printed install command
        #[arg(long)]
        instance: Option<String>,
    },
    /// Cut a node off the mesh, keeping its name
    // Spec §4.4: its bearer token stops working on its very next poll, and
    // its services are removed.
    Revoke {
        /// The node's name
        name: String,
    },
    /// Delete a revoked node and free its name
    // Refused while the node is still active.
    Delete {
        /// The node's name
        name: String,
    },
    /// List all nodes
    // Spec §4.5.1. The columns an admin looks for at a glance; `node show`
    // has every field.
    List {
        /// Print the coordinator's response as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
    /// Show every field of one node
    Show {
        /// The node's name
        name: String,
    },
    /// Show which services a node reaches, and why
    Access {
        /// The node's name
        name: String,
    },
    /// Forget the public address a node advertises
    // For a node that lost the address peers were dialing (a dropped port
    // forward, a move behind CGNAT). It reports a new one on its next poll
    // if it still has one set locally.
    ClearEndpoint {
        /// The node's name
        name: String,
        /// Forget only the address it was found at over this IP version
        // Leaves the explicit override and the other family untouched.
        #[arg(long, value_parser = ["v4", "v6"])]
        family: Option<String>,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// List services and whether they are approved
    List {
        /// Only those waiting for approval
        #[arg(long)]
        pending: bool,
        /// Print the coordinator's response as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
    /// Approve a service, published by the given node only
    // Approval binds to this node — it does not reserve the name for
    // anyone else.
    Approve {
        /// The service's name
        service: String,
        /// The node that publishes it
        #[arg(long, required = true)]
        node: String,
    },
    /// Refuse a service, or withdraw its approval
    // For mistakes. For a node you no longer trust use `node revoke`: a
    // denied service still holds its globally-unique name until the
    // declaring node withdraws it, and a compromised node will not.
    Deny {
        /// The service's name
        service: String,
        /// The node that publishes it
        #[arg(long, required = true)]
        node: String,
        /// Shown to the node
        #[arg(long)]
        reason: Option<String>,
    },
    /// Show who reaches a service, and why
    Access {
        /// The service's name
        name: String,
    },
}

#[derive(Subcommand)]
enum TransitAction {
    /// Allow a node to relay for others, and to be an exit
    // The node must also opt in itself (`wireserve transit on`, and `exit
    // on` to be an exit). A relay can't read or forge what it relays, but
    // sees who talks to whom and can drop it; an exit reads everything it
    // sends on. Revoke and rejoin both withdraw the approval.
    Approve {
        /// The node's name
        name: String,
    },
    /// Withdraw that approval
    // New carrier choices at once; the pairs it carried move off it on
    // their next poll, and devices relying on it need refreshing.
    Deny {
        /// The node's name
        name: String,
    },
    /// List the public relay ports devices use, and whether they are open
    // PLAN.md M40: on which carrier and address each must be open, which
    // node it leads to and which devices rely on it. A port no device
    // relies on any more may be closed again.
    Ports {
        /// Print the coordinator's response as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum DeviceAction {
    /// Add a device and write its WireGuard config
    // Spec §9: an agent-less, consumer-only peer, such as a phone.
    Create(DeviceArgs),
    /// Replace a device's key and write its new config; the old one stops working
    // Keeps its name and mesh address. Destructive from its first request:
    // the device is briefly absent from the mesh while the new key is
    // redeemed. Refuses outright if the name belongs to an agent node.
    Refresh(DeviceArgs),
}

#[derive(clap::Args)]
struct DeviceArgs {
    /// The device's name
    name: String,
    /// Write the config to this file instead of printing it
    #[arg(long, value_name = "FILE")]
    out: Option<std::path::PathBuf>,
    /// Also show the config as a QR code for the WireGuard app
    // Refuses rather than print an unscannably wide code; use --out for a
    // config too large to fit a terminal.
    #[arg(long)]
    qr: bool,
    /// Also write a profile that sends all internet traffic through NODE
    // A full tunnel with the same key and address, switched on in the
    // WireGuard app for public Wi-Fi or a home connection abroad. NODE
    // reads that traffic, as any exit does; the mesh stays end to end.
    // IPv4 only: the device's IPv6 is dropped rather than leaked. NODE must
    // run `wireserve exit on`; without a name, the one node that qualifies
    // is picked. Needs --dns, and --out or --qr, since there are two files.
    #[arg(long, requires = "dns", value_name = "NODE", num_args = 0..=1, default_missing_value = "")]
    exit: Option<String>,
    /// Write the config even if a relay port can't be confirmed open
    // For a port you know is open, or a check that can't reach it from the
    // coordinator's network.
    #[arg(long)]
    allow_unverified: bool,
    /// The DNS server for --exit or --mesh-dns: a service name or an IPv4 address
    // A service by name (a Pi-hole published on 53, say, which then also
    // answers the mesh's own names), or an address such as 9.9.9.9.
    #[arg(long, value_name = "SERVICE|IPV4")]
    dns: Option<String>,
    /// Also use --dns in the mesh profile; all of the device's DNS then goes to it
    // So every service has a name on the device, not only the HTTP ones.
    // The resolver must be on the mesh and answer everything: if it is
    // down, the device has no DNS until the tunnel is switched off.
    #[arg(long, requires = "dns")]
    mesh_dns: bool,
}

#[derive(Subcommand)]
enum GroupAction {
    /// Create an empty group
    Create {
        /// The group's name
        name: String,
    },
    /// Delete an unused group
    // Refused for `default`, and while services, grants or waiting
    // declarations use it — its services would become public.
    Delete {
        /// The group's name
        name: String,
    },
    /// List groups, their grants and services
    List {
        /// Print the coordinator's response as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
    /// Put a service in a group, taking it out of `default`
    // The service need not exist yet.
    Add {
        /// The group's name
        group: String,
        /// The service's name
        service: String,
    },
    /// Take a service out of a group
    // Out of its last one, it is back in `default`.
    Remove {
        /// The group's name
        group: String,
        /// The service's name
        service: String,
    },
}

#[derive(Subcommand)]
enum GrantAction {
    /// Let SOURCE reach every service in a group
    Add {
        /// `everyone`, `oidc:<group>` or `tag:<tag>`
        source: String,
        /// The group's name
        group: String,
    },
    /// Remove a grant
    Remove {
        /// `everyone`, `oidc:<group>` or `tag:<tag>`
        source: String,
        /// The group's name
        group: String,
    },
    /// List grants
    List {
        /// Print the coordinator's response as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum OwnerAction {
    /// Print a sign-in link that makes whoever uses it the device's owner
    // The node then reaches what their groups at the identity provider are
    // granted. Works once, for ten minutes.
    Link {
        /// The device's name
        node: String,
        /// Also show it as a QR code
        #[arg(long)]
        qr: bool,
    },
    /// Remove a device's owner
    // Its outstanding claim links stop working too.
    Clear {
        /// The device's name
        node: String,
    },
}

#[derive(Subcommand)]
enum TagAction {
    /// Tag a node
    Add {
        /// The node's name
        node: String,
        /// The tag
        tag: String,
    },
    /// Remove a tag from a node
    Remove {
        /// The node's name
        node: String,
        /// The tag
        tag: String,
    },
    /// List tags and their nodes
    List {
        /// Only this tag
        tag: Option<String>,
        /// Print each tag's nodes as JSON, for scripts
        #[arg(long)]
        json: bool,
    },
}

/// Prints the join token's deadline immediately under the token itself.
///
/// The operator is about to copy that token into a chat window and walk
/// to another machine; the one moment the expiry is useful is this one.
/// Discovering it instead from a `join` that fails half an hour later
/// tells them only that something is wrong, not what.
/// A claim link (PLAN.md M38), for the device's owner — to stderr, like the
/// QR codes: it is for a person, and it is as good as their sign-in for ten
/// minutes, so it should not end up in a pipe or a file by accident.
fn print_claim(claim: &wireserve_types::ClaimLink, qr: bool) {
    eprintln!();
    eprintln!("Optional: whoever this device belongs to can claim it, and it then reaches what their");
    eprintln!("groups are granted. Send them this link, and nobody else — it works once, until");
    eprintln!("{}:", claim.expires_at.to_rfc3339());
    eprintln!("  {}", clean(&claim.url));
    if qr {
        match wireserve_admin::qr::render(&claim.url) {
            Ok(rendered) => {
                eprintln!();
                eprint!("{rendered}");
                eprintln!("\nOr scan this with the phone's camera to claim it.");
            }
            Err(e) => eprintln!("(no QR code for the link: {e})"),
        }
    }
}

fn print_expiry(expires_at: Option<chrono::DateTime<chrono::Utc>>) {
    match expires_at {
        Some(t) => println!("  redeemable until: {}", t.to_rfc3339()),
        None => println!("  redeemable until: no expiry (token never becomes invalid on its own)"),
    }
}

fn main() {
    if let Err(e) = run(Cli::parse()) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let Cli {
        coordinator_url,
        admin_token,
        register_url,
        command,
    } = cli;

    match command {
        Command::Node { action: NodeAction::Create { name, kind, ttl, instance } } => {
            check_name(&name)?;
            check_instance(instance.as_deref())?;
            let kind: NodeKind = kind.parse()?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_create_node(&client, &name, kind, ttl)?;
            println!("node '{}' created — join token: {}", resp.name, resp.join_token);
            print_expiry(resp.join_token_expires_at);
            if let Some(claim) = &resp.claim {
                print_claim(claim, false);
            }
            if kind == NodeKind::Agent {
                print_install_instructions(
                    resolve_register_url_best_effort(register_url.as_deref()),
                    instance.as_deref(),
                );
            }
        }
        Command::Node { action: NodeAction::Revoke { name } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_revoke(&client, &name)?;
            println!("node '{name}' revoked");
        }
        Command::Node { action: NodeAction::Rejoin { name, ttl, instance } } => {
            check_name(&name)?;
            check_instance(instance.as_deref())?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_rejoin(&client, &name, ttl)?;
            println!(
                "node '{}' rejoined — new join token: {}",
                resp.name, resp.join_token
            );
            print_expiry(resp.join_token_expires_at);
            // `rejoin`'s response doesn't carry the node's kind (unlike
            // `node create`, which has it from the --kind flag), and a
            // static peer's `device refresh` covers its own re-registration
            // anyway — an operator rejoining a static node manually is not
            // a case this needs to guess at, so this always assumes agent.
            print_install_instructions(
                resolve_register_url_best_effort(register_url.as_deref()),
                instance.as_deref(),
            );
        }
        Command::Node { action: NodeAction::Delete { name } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_delete_node(&client, &name)?;
            println!("node '{name}' deleted");
        }
        Command::Node { action: NodeAction::ClearEndpoint { name, family } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_clear_endpoint(&client, &name, family.as_deref())?;
            match &family {
                Some(f) => println!("node '{name}' {f} endpoint cleared"),
                None => println!("node '{name}' endpoint cleared"),
            }
        }
        Command::Service { action: ServiceAction::List { pending, json } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let mut resp = wireserve_admin::cmd_list_services(&client)?;
            if pending {
                resp.services.retain(|s| s.state == wireserve_types::ServiceApprovalState::Pending);
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if resp.services.is_empty() {
                println!("{}", if pending { "no service is waiting for approval" } else { "no services" });
            } else {
                print!("{}", wireserve_admin::listing::services(&resp.services));
            }
        }
        Command::Service { action: ServiceAction::Approve { service, node } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_approve_service(&client, &node, &service)?;
            println!("service '{service}' approved for node '{node}'");
        }
        Command::Group { action } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            match action {
                GroupAction::Create { name } => {
                    if wireserve_admin::cmd_create_group(&client, &name)? {
                        println!("group '{name}' created; put services in it with `group add {name} <service>`");
                    } else {
                        println!("group '{name}' already exists");
                    }
                }
                GroupAction::Delete { name } => {
                    wireserve_admin::cmd_delete_group(&client, &name)?;
                    println!("group '{name}' deleted");
                }
                GroupAction::List { json } => {
                    let resp = wireserve_admin::cmd_list_groups(&client)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else {
                        print!("{}", wireserve_admin::listing::groups(&resp));
                    }
                }
                GroupAction::Add { group, service } => {
                    let m = wireserve_admin::cmd_set_member(&client, &group, &service, true)?;
                    println!("'{service}' is in {} from its node's next poll", m.groups.join(", "));
                }
                GroupAction::Remove { group, service } => {
                    let m = wireserve_admin::cmd_set_member(&client, &group, &service, false)?;
                    if m.groups == [wireserve_types::DEFAULT_GROUP] {
                        println!("'{service}' is back in default — reachable by whoever default is granted to");
                    } else {
                        println!("'{service}' is in {}", m.groups.join(", "));
                    }
                }
            }
        }
        Command::Grant { action } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            match action {
                GrantAction::Add { source, group } => {
                    if wireserve_admin::cmd_set_grant(&client, &source, &group, true)? {
                        println!("{source} may reach every service in '{group}' from the next poll");
                    } else {
                        println!("{source} already may reach '{group}'");
                    }
                }
                GrantAction::Remove { source, group } => {
                    wireserve_admin::cmd_set_grant(&client, &source, &group, false)?;
                    println!("{source} no longer reaches '{group}' through this grant, from the next poll");
                }
                GrantAction::List { json } => {
                    let resp = wireserve_admin::cmd_list_grants(&client)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&resp)?);
                    } else if resp.grants.is_empty() {
                        println!("no grants: every service is reached by its own node alone");
                    } else {
                        print!("{}", wireserve_admin::listing::grants(&resp));
                    }
                }
            }
        }
        Command::Tag { action } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            match action {
                TagAction::Add { node, tag } => {
                    wireserve_admin::cmd_set_tag(&client, &node, &tag, true)?;
                    println!("node '{node}' is tagged '{tag}'");
                }
                TagAction::Remove { node, tag } => {
                    wireserve_admin::cmd_set_tag(&client, &node, &tag, false)?;
                    println!("node '{node}' is no longer tagged '{tag}'");
                }
                TagAction::List { tag, json } => {
                    if let Some(tag) = &tag {
                        check_name(tag)?;
                    }
                    let resp = wireserve_admin::cmd_list_peers(&client)?;
                    let mut by_tag = wireserve_admin::tags_by_tag(&resp);
                    if let Some(tag) = &tag {
                        by_tag.retain(|t, _| t == tag);
                    }
                    if json {
                        println!("{}", serde_json::to_string_pretty(&by_tag)?);
                    } else if by_tag.is_empty() {
                        match tag {
                            Some(tag) => println!("no node is tagged '{tag}'"),
                            None => println!("no tags set"),
                        }
                    } else {
                        print!("{}", wireserve_admin::listing::tags(&by_tag));
                    }
                }
            }
        }
        Command::Owner { action: OwnerAction::Link { node, qr } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let claim = wireserve_admin::cmd_claim_link(&client, &node)?;
            print_claim(&claim, qr);
        }
        Command::Owner { action: OwnerAction::Clear { node } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_remove_owner(&client, &node)?;
            println!("node '{node}' belongs to nobody now, from its next poll");
        }
        Command::Node { action: NodeAction::Access { name: node } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let r = wireserve_admin::cmd_node_access(&client, &node)?;
            if let Some(o) = &r.owner {
                let who = o.email.as_deref().or(o.name.as_deref()).unwrap_or(&o.sub);
                println!(
                    "{} belongs to {}{}",
                    clean(&r.node),
                    clean(who),
                    if o.stale { " (its groups could not be refreshed for over an hour, and count for nothing)" } else { "" }
                );
            }
            println!("{} acts as: {}", clean(&r.node), sources(&r.principals));
            if r.services.is_empty() {
                println!("  reaches no service of another node by who it is");
            }
            let rows: Vec<Vec<String>> =
                r.services.iter().map(|s| vec![format!("  {}", clean(&s.name)), format!("via {}", sources(&s.via))]).collect();
            print!("{}", columns(&rows));
            if r.default_closed {
                println!("note: everyone -> default is not granted; services without a group reach nobody");
            }
        }
        Command::Service { action: ServiceAction::Access { name: service } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let r = wireserve_admin::cmd_service_access(&client, &service)?;
            let owner = r.node.as_deref().map_or_else(|| "nothing declares it yet".to_string(), clean);
            println!("{} ({owner})", clean(&r.service));
            println!("  groups:     {}", r.groups.iter().map(|g| clean(g)).collect::<Vec<_>>().join(", "));
            println!("  granted to: {}", sources(&r.granted_to));
            if r.open {
                println!("  reachable by every node");
            } else {
                println!("  reachable by its own node, and:");
                if r.nodes.is_empty() {
                    println!("    no other node");
                }
                let rows: Vec<Vec<String>> =
                    r.nodes.iter().map(|n| vec![format!("    {}", clean(&n.name)), format!("via {}", sources(&n.via))]).collect();
                print!("{}", columns(&rows));
                if r.sign_in {
                    let groups = r.sign_in_groups.iter().map(|g| clean(g)).collect::<Vec<_>>();
                    println!("  anyone else: the sign-in, with one of {}", groups.join(", "));
                } else if !r.sign_in_groups.is_empty() {
                    println!("  (identity-provider groups are granted, but no sign-in applies: no provider, \
                              no terminator serving it, or its node's agent is too old)");
                }
            }
            if r.default_closed {
                println!("note: everyone -> default is not granted; services without a group reach nobody");
            }
        }
        Command::Service { action: ServiceAction::Deny { service, node, reason } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_deny_service(&client, &node, &service, reason.as_deref())?;
            println!("service '{service}' denied for node '{node}'");
            println!(
                "  the node withdraws it and closes its firewall hole on its next poll \
                 (up to one poll interval from now)"
            );
        }
        Command::Transit { action: TransitAction::Approve { name } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_approve_transit(&client, &name)?;
            println!("node '{name}' approved to carry transit traffic");
            println!(
                "  it carries nothing until it has also run `wireserve transit on`"
            );
        }
        Command::Transit { action: TransitAction::Deny { name } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            wireserve_admin::cmd_deny_transit(&client, &name)?;
            println!("node '{name}' may no longer carry transit traffic");
        }
        Command::Transit { action: TransitAction::Ports { json } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_relay_ports(&client)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if resp.ports.is_empty() {
                println!("no public relay ports: no device reaches a node through a carrier");
            } else {
                print!("{}", wireserve_admin::listing::relay_ports(&resp));
            }
        }
        Command::Node { action: NodeAction::List { json } } => {
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_list_peers(&client)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            } else if resp.peers.is_empty() {
                println!("no nodes yet: add one with `node create <name>`");
            } else {
                print!("{}", wireserve_admin::listing::nodes(&resp, chrono::Utc::now()));
            }
        }
        Command::Node { action: NodeAction::Show { name } } => {
            check_name(&name)?;
            let client = build_client(&coordinator_url, &admin_token)?;
            let resp = wireserve_admin::cmd_list_peers(&client)?;
            let peer = resp.peers.iter().find(|p| p.name == name).ok_or_else(|| format!("no node named '{name}' on the mesh"))?;
            print!("{}", wireserve_admin::listing::node(&resp, peer, chrono::Utc::now()));
        }
        Command::Device { action } => {
            let (refresh, DeviceArgs { name, out, qr, exit, allow_unverified, dns, mesh_dns }) = match action {
                DeviceAction::Create(args) => (false, args),
                DeviceAction::Refresh(args) => (true, args),
            };
            check_name(&name)?;
            if let Some(exit) = exit.as_deref().filter(|e| !e.is_empty()) {
                check_name(exit)?;
            }
            let wants_exit = exit.is_some();
            // Before any request: two profiles cannot both go to stdout.
            if wants_exit && out.is_none() && !qr {
                return Err("--exit writes a second profile; pass --out <file> (the full-tunnel one \
                            goes beside it as <file>-exit.conf) or --qr"
                    .into());
            }
            if dns.is_some() && !wants_exit && !mesh_dns {
                return Err("--dns needs --exit (the full-tunnel profile) or --mesh-dns (the mesh \
                            profile), to say which profile it goes into"
                    .into());
            }
            let opts = wireserve_admin::export_config::ExportOptions {
                exit: exit.as_deref(),
                dns: dns.as_deref(),
                mesh_dns,
                allow_unverified,
            };
            let client = build_client(&coordinator_url, &admin_token)?;
            let register_url = config::resolve_register_url_interactive(register_url.as_deref())?;
            warn_if_plaintext_to_remote_host(&register_url);
            let exported = if refresh {
                wireserve_admin::cmd_export_config_refresh(&client, &register_url, &name, &opts)?
            } else {
                wireserve_admin::cmd_export_config(&client, &register_url, &name, &opts)?
            };
            let conf = &exported.conf;
            // By now the export has happened — a refresh has already retired
            // the old key — so a code that can't be drawn must not lose the
            // config: it is printed instead, as without --qr.
            let rendered_qr = qr.then(|| wireserve_admin::qr::render(conf));
            let rendered_exit_qr = exported.exit_conf.as_ref().filter(|_| qr).map(|c| wireserve_admin::qr::render(c));
            let qr_failed = [&rendered_qr, &rendered_exit_qr].iter().any(|r| matches!(r, Some(Err(_))));
            match &out {
                None if qr_failed => {
                    print!("{conf}");
                    if let Some(exit_conf) = &exported.exit_conf {
                        print!("\n# ---- full tunnel ----\n{exit_conf}");
                    }
                }
                Some(path) => {
                    write_conf_file(path, conf)?;
                    if let Some(exit_conf) = &exported.exit_conf {
                        let exit_path = exit_conf_path(path);
                        write_conf_file(&exit_path, exit_conf)?;
                        eprintln!("wrote the full-tunnel profile to {}", exit_path.display());
                    }
                }
                None => print!("{conf}"),
            }
            for (label, rendered) in [("", rendered_qr), (" (full tunnel)", rendered_exit_qr)] {
                let rendered = match rendered {
                    None => continue,
                    Some(Ok(r)) => r,
                    Some(Err(e)) => {
                        eprintln!(
                            "\nno QR code{label}: {e}. The config is {} — nothing is lost, and this \
                             export does not need running again.",
                            if out.is_some() { "in the file" } else { "printed above" }
                        );
                        continue;
                    }
                };
                // stderr: the config on stdout is the program's output and
                // stays pipeable, the code is for a human looking at it.
                eprintln!();
                eprint!("{rendered}");
                eprintln!("\nScan with the WireGuard app{label}. This code contains the private key —");
                eprintln!("it stays in your scrollback and in any screen recording.");
            }
            if wants_exit && exported.exit_conf.is_none() {
                eprintln!("warning: no full-tunnel profile was written — its exit is not in the config, see above");
            } else if wants_exit {
                eprintln!(
                    "\nImport both on the device and switch on the -exit one for public Wi-Fi or \
                     to browse from home; the WireGuard app runs only one tunnel at a time."
                );
            }
            if let Some(claim) = &exported.claim {
                print_claim(claim, qr);
            }
            if refresh {
                eprintln!(
                    "\nDelete the old '{name}' tunnel on the device before importing this one: \n\
                     the address is unchanged, so the stale config still looks valid and two \n\
                     tunnels would claim the same address."
                );
            }
        }
    }
    Ok(())
}

/// Grant sources for a person: `everyone, tag:servers`, or `-`.
fn sources(v: &[wireserve_types::GrantSource]) -> String {
    if v.is_empty() {
        "-".to_string()
    } else {
        v.iter().map(|s| clean(&s.to_string())).collect::<Vec<_>>().join(", ")
    }
}

/// Spec §3: fail fast on an obviously invalid name before resolving config
/// or making any network call.
fn check_name(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if wireserve_types::is_valid_dns_label(name) {
        Ok(())
    } else {
        Err(format!("invalid name: {name}").into())
    }
}

/// `--instance` is never sent to the coordinator — it only ends up
/// interpolated into the printed `wireserve install` command — but
/// spec §3's fail-fast rule still applies, and a name that broke that
/// command's syntax would be a worse failure mode than rejecting it here.
/// Mirrors `wireserve_agent::paths::Instance::new`'s rule (1-32 chars,
/// alphanumeric/`_`/`-`, starting alphanumeric); wireserve-admin doesn't
/// depend on the agent crate, so this is a small standalone check rather
/// than a shared one.
fn check_instance(instance: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    let Some(name) = instance else { return Ok(()) };
    let ok = (1..=32).contains(&name.len())
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!(
            "invalid instance name '{name}': use 1-32 characters from A-Z, a-z, 0-9, '_', '-', \
             starting with a letter or digit"
        )
        .into())
    }
}

/// Writes the rendered `.conf` at mode 600 from the moment of creation
/// (security review S5) — it contains a WireGuard private key, the same
/// sensitivity spec §7 requires for the agent's own local key material,
/// even though this file lives on the *admin operator's* machine rather
/// than the node's own disk that §7 literally describes.
#[cfg(unix)]
fn write_conf_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(contents.as_bytes())
}

#[cfg(not(unix))]
fn write_conf_file(path: &std::path::Path, contents: &str) -> std::io::Result<()> {
    std::fs::write(path, contents)
}

/// `foo.conf` → `foo-exit.conf`; a name without an extension just gains
/// `-exit`. The WireGuard apps name an imported tunnel after its file, so
/// the two profiles arrive as `<name>` and `<name>-exit`.
fn exit_conf_path(path: &std::path::Path) -> std::path::PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let name = match path.extension() {
        Some(ext) => format!("{stem}-exit.{}", ext.to_string_lossy()),
        None => format!("{stem}-exit"),
    };
    path.with_file_name(name)
}

fn build_client(
    coordinator_url: &Option<String>,
    admin_token: &Option<String>,
) -> Result<AdminClient, Box<dyn std::error::Error>> {
    let url = config::resolve_coordinator_url_interactive(coordinator_url.as_deref())?;
    warn_if_plaintext_to_remote_host(&url);
    let token = config::resolve_admin_token_interactive(admin_token.as_deref())?;
    Ok(AdminClient::new(url, token))
}

/// Resolves the register URL the same way `device create` does (flag → env
/// → saved file), but never prompts and never fails the caller — used by
/// `node create`/`node rejoin`, where this is a bonus annotation on already
/// successful output, not a requirement for the command itself.
fn resolve_register_url_best_effort(cli_flag: Option<&str>) -> Option<String> {
    config::resolve_register_url(cli_flag).ok()
}

/// Printed after a fresh join token, right where the operator is looking —
/// the actual single command to run on the new machine (`wireserve
/// install`, which installs the binary and systemd unit, then joins),
/// not just the token it needs. Deliberately does not embed the token
/// itself: a token as a command-line argument lands in shell history and
/// `ps` output (S7, the agent's own doc comment on its
/// `join_token` argument), which `install`/`join`'s interactive prompt
/// exists to avoid — so the command printed here has no secret in it,
/// and the token is pasted in response to that prompt instead.
fn print_install_instructions(register_url: Option<String>, instance: Option<&str>) {
    let instance_flag = instance_flag_suffix(instance);
    println!();
    println!("To add this node to the mesh:");
    match register_url {
        Some(url) => println!("  sudo wireserve install {url}{instance_flag}"),
        None => {
            println!("  sudo wireserve install <this coordinator's public URL>{instance_flag}");
            println!(
                "  (pass --register-url, or set WIRESERVE_REGISTER_URL, so this command is \
                 filled in for you)"
            );
        }
    }
    println!("  (needs the wireserve binary already on that machine, and root)");
    println!("  then paste the join token above when prompted");
}

/// `" --instance <name>"`, or empty for the default instance (implicit
/// or explicit) — so the printed command only mentions `--instance` when
/// it actually matters.
fn instance_flag_suffix(instance: Option<&str>) -> String {
    match instance {
        Some(name) if name != "default" => format!(" --instance {name}"),
        _ => String::new(),
    }
}

/// Security review S6: neither client here refuses plain `http://` to a
/// non-loopback host — the admin bearer token (and, for /register, a
/// join token) would go over the wire in clear. Spec §7 assumes a
/// TLS-terminating reverse proxy sits between any real client and the
/// coordinator, so this is very likely a misconfiguration rather than an
/// intentional choice whenever the host isn't loopback. A warning rather
/// than a hard refusal: `http://127.0.0.1:...` (the loopback/docker-exec
/// pattern this project's own deploy docs recommend) is completely
/// legitimate and must keep working without a flag to silence a false
/// alarm.
fn warn_if_plaintext_to_remote_host(url: &str) {
    if wireserve_types::is_plaintext_http_to_remote_host(url) {
        eprintln!(
            "warning: sending requests to {url} over plain HTTP — the admin token (and any \
             join token) will be sent in clear over the network. Spec §7 assumes a \
             TLS-terminating reverse proxy in front of the coordinator; use an https:// URL \
             unless this really is a loopback/trusted-local connection."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(words: &[&str]) -> Result<Command, clap::Error> {
        Cli::try_parse_from(std::iter::once("wireserve-admin").chain(words.iter().copied())).map(|c| c.command)
    }

    #[test]
    fn the_cli_is_well_formed() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn approving_a_service_names_its_node_by_flag() {
        let Ok(Command::Service { action: ServiceAction::Approve { service, node } }) =
            parse(&["service", "approve", "web", "--node", "lego2"])
        else {
            panic!("not a service approval")
        };
        assert_eq!((service.as_str(), node.as_str()), ("web", "lego2"));
        // The order before M44, node first: refused, not swapped.
        assert!(parse(&["service", "approve", "lego2", "web"]).is_err());
    }

    #[test]
    fn a_refresh_is_its_own_command() {
        assert!(matches!(parse(&["device", "refresh", "phone"]), Ok(Command::Device { action: DeviceAction::Refresh(_) })));
        assert!(parse(&["device", "create", "phone", "--refresh"]).is_err());
    }

    #[test]
    fn kind_and_family_take_only_known_values() {
        assert!(parse(&["node", "create", "pc", "--kind", "static"]).is_ok());
        assert!(parse(&["node", "create", "pc", "--kind", "statik"]).is_err());
        assert!(parse(&["node", "clear-endpoint", "pc", "--family", "v6"]).is_ok());
        assert!(parse(&["node", "clear-endpoint", "pc", "--family", "ipv6"]).is_err());
    }

    #[test]
    fn write_conf_file_creates_file_at_mode_600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wg0.conf");
        write_conf_file(&path, "[Interface]\nPrivateKey = secret\n").unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("PrivateKey = secret"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "exported .conf contains a private key and must be mode 600");
    }

    #[test]
    fn warn_if_plaintext_does_not_panic_on_various_inputs() {
        // No assertions on stderr output — just confirms these don't panic
        // on malformed/edge-case URLs (empty host, https, no scheme, etc.).
        for url in ["http://127.0.0.1:8081", "https://example.com", "not-a-url", "http://"] {
            warn_if_plaintext_to_remote_host(url);
        }
    }

    #[test]
    fn check_instance_accepts_none_and_valid_names() {
        assert!(check_instance(None).is_ok());
        assert!(check_instance(Some("work")).is_ok());
        assert!(check_instance(Some("a")).is_ok());
        assert!(check_instance(Some(&"a".repeat(32))).is_ok());
    }

    #[test]
    fn check_instance_rejects_invalid_names() {
        assert!(check_instance(Some("")).is_err());
        assert!(check_instance(Some(&"a".repeat(33))).is_err());
        assert!(check_instance(Some("-work")).is_err(), "must start alphanumeric");
        assert!(check_instance(Some("has space")).is_err());
        assert!(check_instance(Some("has/slash")).is_err());
    }

    #[test]
    fn instance_flag_suffix_omits_default_and_none() {
        assert_eq!(instance_flag_suffix(None), "");
        assert_eq!(instance_flag_suffix(Some("default")), "");
    }

    #[test]
    fn instance_flag_suffix_includes_named_instance() {
        assert_eq!(instance_flag_suffix(Some("work")), " --instance work");
    }
}
