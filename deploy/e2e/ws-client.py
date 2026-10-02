#!/usr/bin/env python3
# A WebSocket client for run-tls-terminate-test.sh (PLAN.md M42): opens
# `url` at `address`:443 with TLS verified against `cafile`, offering the
# `chat` subprotocol, and prints the chosen subprotocol, the backend's first
# message and the echo of one of its own.
#
# Usage: ws-client.py <wss url> <address> <cafile>
import asyncio
import socket
import ssl
import sys

import websockets

URL, ADDRESS, CAFILE = sys.argv[1:4]


async def main():
    tls = ssl.create_default_context(cafile=CAFILE)
    sock = socket.create_connection((ADDRESS, 443), timeout=10)
    sock.settimeout(None)
    name = URL.split("/")[2]
    async with websockets.connect(URL, ssl=tls, sock=sock, server_hostname=name, subprotocols=["chat"]) as ws:
        print(f"subprotocol={ws.subprotocol}")
        print(await asyncio.wait_for(ws.recv(), 10))
        await ws.send("over the mesh")
        print(f"echo={await asyncio.wait_for(ws.recv(), 10)}")


asyncio.run(main())
