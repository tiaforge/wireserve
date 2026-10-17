# Windows nodes

A Windows 10 or 11 computer (x86_64) can join the mesh as a node: it gets
its own mesh address, talks to every other node directly over WireGuard,
and reaches every service it is allowed to by its `<service>.wg` name, the
same as a Linux node.

What a Windows node does **not** do, yet:

- **serve anything**: no `wireserve <service> <port>`, so no services, no
  HTTPS for them, and no TLS terminator;
- **carry traffic** for others: no `transit` and no `exit`.

A Windows node refuses those commands. Use a Linux machine for anything
that serves; a Windows node is for using the mesh.

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
2. creates the **`wireserve-agent`** Windows service, which runs as
   LocalSystem, starts with Windows and is restarted if it fails;
3. joins the mesh;
4. starts the service and waits until it runs.

`install` does not add `C:\Program Files\wireserve` to `PATH`; run the
commands below with the full path, or add it yourself.

## Using it

Every command talks to the running service, and only administrators may:
run them from an elevated terminal.

```powershell
& "C:\Program Files\wireserve\wireserve.exe" status
& "C:\Program Files\wireserve\wireserve.exe" leave
```

`status` shows the mesh's services and peers. `leave` takes the node out
of the mesh, as on Linux, and also removes the `wireserve-agent` service.
To join again, run `install` again with a new join token.

To upgrade, run `install` from the new release's folder, without a URL or
token: it stops every agent service on the computer, replaces the
installed files, and starts them again, keeping each one's identity.

## Several agents on one computer

As on Linux, `--instance <name>` runs another agent with its own identity,
for another mesh or another identity in the same one: `install --instance
work` creates a `wireserve-agent-work` service, and every other command
takes the same flag.

## What it changes on the computer

- **A network adapter** named `wireserve0` (the first free of
  `wireserve0` … `wireserve15`), of type *WireServe Tunnel*. It exists only
  while the agent runs: stopping the service, or the agent crashing,
  removes it. Windows lists it as an unidentified, public network; that
  does not matter to the firewall below.
- **Firewall rules** in the Windows Filtering Platform: every new inbound
  connection over the mesh is blocked, on the mesh adapter and to the
  node's mesh addresses, while replies to the computer's own connections
  come back as usual. The rules sit above Windows Defender Firewall (or
  whatever firewall replaced it), so another firewall cannot open them,
  and they go when the agent stops. `netsh wfp show filters` lists them,
  named `wireserve: block inbound on wireserve0`.
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
  own folder under `instances\`), kept to about 10 MiB.

## Troubleshooting

- **`install` says it needs an elevated terminal**: open PowerShell with
  *Run as administrator*. Being an administrator is not enough on its own;
  Windows runs your terminal unelevated unless asked.
- **The service stops right after starting**: `install` says so and names
  the log; the reason is at its end.
- **`wireguard.dll must be next to wireserve.exe`**: unpack the whole zip
  and run `install` from that folder.
- **`not permitted to use the wireserve daemon`**: the command was run
  from an unelevated terminal.
