# ADR-0010: the official MCP Python SDK for transport and tool registration

## Status

Accepted.

## Context

The gateway needs an MCP server over streamable HTTP. Two candidates: the official
MCP Python SDK (`mcp` on PyPI) and the standalone FastMCP (`fastmcp`). Three things
had to hold: it serves stateless streamable HTTP mounted inside a FastAPI app; a
tool handler can reach the per-request Starlette request; and it implements a
current protocol revision.

## Decision

Use the official SDK, `mcp` 2.2.0 (it implements protocol revision `2026-07-28`).
`FastMCP` was renamed `MCPServer` in v2; the server is built with
`MCPServer(...).streamable_http_app(streamable_http_path="/mcp", json_response=True,
stateless_http=True)`, and its session-manager lifespan is entered from FastAPI's
lifespan. Mounting registers `/mcp` as an exact route, so `POST /mcp` is not
redirected to `/mcp/`. Auth runs as ASGI middleware on the `/mcp` mount, which puts
the verified principal into the request scope's `state`; tools read it from the
SDK's per-request context (`ctx.request_context.request.state`), not a contextvar,
because contextvars may not cross into the SDK's task group. JSON-response mode
sends the response start after the tool completes, so a send-wrapper can add the
`Server-Timing` header the latency benchmark reads.

## Consequences

The gateway is stateless, so replicas behave identically and there is no session
to hijack. The SDK ships its own transport client (on `httpx2`), which the red-team
runner and the LLM harness use. The design was verified by a runnable spike before
adoption; the concurrency test in the MCP tools guards the per-request principal
path.
