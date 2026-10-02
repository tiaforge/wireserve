#!/usr/bin/env python3
# A WebSocket test backend for run-tls-terminate-test.sh (PLAN.md M42):
# its first message names what reached it — the forwarding headers and the
# caller — and after that it echoes. It takes the `chat` subprotocol when
# offered. Written for both the websockets 10 of Debian bookworm and later
# releases, whose handler and request APIs differ.
import asyncio
import sys

import websockets

PORT = int(sys.argv[1])
SHOWN = ["x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-wireserve-node", "host"]


async def handler(ws, *_path):
    request = getattr(ws, "request", None)
    headers = request.headers if request is not None else ws.request_headers
    await ws.send("\n".join(f"{name}={headers.get(name, '')}" for name in SHOWN))
    async for message in ws:
        await ws.send(message)


async def main():
    async with websockets.serve(handler, "0.0.0.0", PORT, subprotocols=["chat"]):
        await asyncio.Future()


asyncio.run(main())
