# Windows nodes

A Windows 10 or 11 computer (x86_64) can join the mesh as a node: it gets
its own mesh address, talks to every other node directly over WireGuard,
and reaches every service it is allowed to by its `<service>.wg` name, the
same as a Linux node.

It can also publish services, with HTTPS under their names, as a Linux
node does. What it does not do yet is listed under
[Not on Windows yet](#not-on-windows-yet).

## Not on Windows yet

What works on Linux and not, or differently, on Windows:

- **Publishing a port as another one** (`wireserve ssh 2222:22`) is
  refused, but for TCP 80 and 443, which the TLS terminator passes on to any
  port. Publish the port the service listens on (`wireserve ssh 22`).
- **Publishing a service on another address** (`80:192.168.1.1:80`, a
  router or printer on the computer's network) is refused.
- **Port 80 without the terminator**: while the terminator does not answer
  a service's 80 (just installed, or stopped), an `80:3000` service is
  closed on 80, where Linux passes it straight to the service. An `80`
  published as itself still gets through, marked `(80 unguarded)`.
- **Where the service listens**: on every address (`0.0.0.0`) or on the
  service's own address. On the node's mesh address alone it is not
  reached, as it would be on Linux.
- **Carrying traffic for others**: no `transit`, no relaying for other
  nodes, no `exit`. The commands are refused.
- **`wireserve-admin` and the coordinator** do not run on Windows: manage
  the mesh from a Linux machine.
- **`install --tls-port`** is refused: the terminator listens on each
  service's own 443 and 80.
- **Downloads**: a zip, for x86_64 only (no ARM64), with an unsigned
  `wireserve.exe`, which SmartScreen warns about.
- **The adapter's name** changes between `wireserve0` and `wireserve1` on
  every restart of the service, while Windows still removes the old one.
  Nothing depends on the name.

## Installing

Download `wireserve-<version>-x86_64-windows.zip` from the
[releases page](https://github.com/tiaforge/wireserve/releases) and unpack
it. Keep `wireserve.exe` and `wireguard.dll` together: the agent loads the
DLL from its own folder and nowhere else.

On the admin side, create the node as for any other
([Adding nodes](nodes.md)):

```sh
wireserve-admin node create laptop
```

Then, on the Windows computer, open PowerShell **as administrator** (right
click → Run as administrator) and run:

```powershell
.\wireserve.exe install https://wireserve.example.com
```

It asks for the join token. `install`:

1. copies `wireserve.exe` and `wireguard.dll` to
   `C:\Program Files\wireserve\`;
2. adds that folder to the system `Path`;
3. creates the local **`wireserve`** group (see below);
4. creates the **`wireserve-agent`** Windows service, which runs as
   LocalSystem, starts with Windows and is restarted if it fails;
5. creates the **`wireserve-tls`** service beside it, the TLS terminator,
   which runs as an account of its own (see [Serving](#serving));
6. joins the mesh;
7. starts both services and waits until they run.

Terminals opened before `install` don't see the new `Path`; open a new
one, or use the full path, `& "C:\Program Files\wireserve\wireserve.exe"`.

## Using it

Every command talks to the running service, which only administrators,
from an elevated terminal, and members of the `wireserve` group may.

```powershell
wireserve status
wireserve leave
```

To use it without elevating, join the group, from an elevated terminal,
and sign out and in again (Windows reads your groups at sign-in):

```powershell
net localgroup wireserve <user> /add
```

Membership lets someone do anything the commands do, `leave` included,
as the `wireserve` group does on Linux. The service shares its pipe with
the group only if the group existed when it started, so a group you
create yourself takes a restart of the service. Set
`WIRESERVE_SOCKET_GROUP` system-wide to use another local group, or to
empty to share with none. Only a group of the computer's own counts, never
a domain's of the same name.

`status` shows the mesh's services and peers. `leave` takes the node out
of the mesh, as on Linux, and also removes the `wireserve-agent` and
`wireserve-tls` services.
To join again, run `install` again with a new join token.

To upgrade, run `install` from the new release's folder, without a URL or
token: it stops every wireserve service on the computer, agents and
terminators, replaces the installed files, and starts them again, keeping
each agent's identity.

## Serving

As on Linux ([Publishing services](services.md)), from an elevated
terminal or as a member of the `wireserve` group:

```powershell
wireserve ssh 22
wireserve grafana 80:3000 443:3000
```

What differs:

- **Ports are published as themselves.** Nothing on Windows rewrites one
  port to another, so `wireserve ssh 2222:22` is refused: publish
  `22`. TCP 80 and 443 are the exception: the TLS terminator answers them
  and passes each request on to the target port, so `80:3000` and
  `443:3000` work as on Linux.
- **The service listens on every address** (`0.0.0.0`), or on the
  service's own address: a service's traffic arrives at that address,
  unrewritten. One bound to the node's mesh address alone, or to
  `127.0.0.1`, is not reached.
- **No terminator, no remapped 80.** While the terminator does not answer
  a service's port 80 (just installed, or stopped), an `80:3000` service is
  closed on 80, where Linux sends it straight to the service. An `80` (on
  80 itself) gets through to the service, and `status` marks it
  `(80 unguarded)`.
- **The terminator is a service of its own**, `wireserve-tls`, running as
  the account `NT SERVICE\wireserve-tls`, which holds nothing of the
  agent's: no WireGuard key, no firewall. It listens on each service
  address's 443 and 80 itself, and the firewall lets in only what that
  account accepts there, so no other program can answer those ports in
  its place. Its certificates are in `C:\ProgramData\wireserve-tls\`,
  readable by that account and administrators only, and so is its log,
  `tls.log`.

## Several agents on one computer

As on Linux, `--instance <name>` runs another agent with its own identity,
for another mesh or another identity in the same one: `install --instance
work` creates a `wireserve-agent-work` service (and `wireserve-tls-work`
beside it), and every other command takes the same flag.

## What it changes on the computer

- **A network adapter** named `wireserve0` (the first free of
  `wireserve0` … `wireserve15`), of type *WireServe Tunnel*. It exists only
  while the agent runs: stopping the service, or the agent crashing,
  removes it. Windows lists it as an unidentified, public network; that
  does not matter to the firewall below.
- **The system `Path`**: `C:\Program Files\wireserve` added at its end,
  once. `leave` keeps it, as it keeps the files there.
- **A local group**, `wireserve`, empty until you add someone.
- **Service addresses**: each service's own mesh address, added to the
  mesh adapter while the service is published. Windows never uses them
  as the source of the computer's own connections.
- **Firewall rules** in the Windows Filtering Platform: every new inbound
  connection over the mesh is blocked, on the mesh adapter and to the
  node's mesh addresses, but for each service's published ports, from the
  nodes and devices its grants admit; replies to the computer's own
  connections come back as usual. The rules sit above Windows Defender
  Firewall (or whatever firewall replaced it), so another firewall cannot
  open them, and they go when the agent stops. `netsh wfp show filters`
  lists them, named `wireserve: block inbound on wireserve0` and
  `wireserve: permit <address>:<port>/<protocol> on wireserve0`.
- **The `wireserve-tls` service** and its folder,
  `C:\ProgramData\wireserve-tls\` (see [Serving](#serving)).
- **The hosts file**, `C:\Windows\System32\drivers\etc\hosts`: a block
  between `# BEGIN WIRESERVE` and `# END WIRESERVE` with every service's
  name, rewritten as the mesh changes. Nothing outside the block is
  touched. A lock file, `.hosts.wireserve-lock`, stays beside it.
- **Routes** to the other nodes' mesh addresses and service addresses,
  through the mesh adapter only. Nothing else is routed through the mesh.
- **Its state** in `C:\ProgramData\wireserve\`: keys, token and the last
  known mesh, readable by SYSTEM and Administrators only. The agent refuses
  a `wireserve` folder there that some other user created.
- **Its log**, `C:\ProgramData\wireserve\agent.log` (an instance's in its
  own folder under `instances\`), kept to about 10 MiB, and the
  terminator's, `C:\ProgramData\wireserve-tls\tls.log`. `ProgramData` is
  a hidden folder, and both are readable by administrators only, so
  Explorer will not open them from a normal account; from an elevated
  PowerShell, `Get-Content C:\ProgramData\wireserve\agent.log -Tail 50 -Wait`.

## Troubleshooting

- **`install` says it needs an elevated terminal**: open PowerShell with
  *Run as administrator*. Being an administrator is not enough on its own;
  Windows runs your terminal unelevated unless asked.
- **The service stops right after starting**: `install` says so and names
  the log; the reason is at its end.
- **`wireguard.dll must be next to wireserve.exe`**: unpack the whole zip
  and run `install` from that folder.
- **`not permitted to use the wireserve daemon`**: the command was run
  from an unelevated terminal by someone not in the `wireserve` group, or
  who joined it without signing out and in again.
- **`wireserve` is not recognized**: the terminal was open before
  `install`; open a new one.
- **A service is unreachable**: check that it listens on every address
  (`netstat -ano | findstr LISTENING` shows `0.0.0.0:<port>`), not on
  `127.0.0.1` or one address alone.
- **HTTPS for a service never comes up**: the reason is at the end of
  `C:\ProgramData\wireserve-tls\tls.log`. "cannot listen on the
  service's address" with "access denied" or "in use" means another
  program holds that address's 443 (or 80) for itself.
