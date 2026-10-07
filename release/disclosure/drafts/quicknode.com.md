To: security@quicknode.com
Contact source: RFC 2142 default (no security.txt found); also try abuse@ and the registrar WHOIS contact
Findings: card_without_endpoint (rank 96717)

Subject: Agent-discovery metadata on quicknode.com: research notice, no action required

Hello {{contact_name_or_team}},

We are researchers at {{institution}} measuring how web sites publish
machine-readable "agent discovery" files (MCP server cards, A2A agent
cards, OAuth protected-resource metadata, llms.txt) across the Tranco
top sites. quicknode.com is in our sample. This is a courtesy notice, not a
vulnerability report in the usual sense; nothing we found exposes data.

What we saw (on 5-6 October 2026, from a residential network in the United States):

- Your MCP server card at https://quicknode.com/.well-known/mcp/server-card.json -> 200 (valid card, no endpoint URL) does not contain an endpoint URL (neither `remotes[].url` nor `url`), so agents cannot connect from it.

How we saw it: our crawler fetched the public well-known paths with a
descriptive User-Agent (AgentDiscoveryCrawler/0.5), at most one request per second
per host. For MCP endpoints named in a valid card we sent one JSON-RPC
`initialize` request without credentials (protocol revision 2025-11-25;
the first request a client sends to a Streamable HTTP endpoint, and the
one on which the authorization specification says a 401 challenge is
delivered), recorded the
response, closed any session the server opened with an HTTP DELETE, and
sent nothing else. We did not list or call tools, and we make no claim
about what an authenticated or further request would have returned.

What the specification says: see below
(MCP authorization: an endpoint that requires authorization answers
`initialize` with 401 and a WWW-Authenticate header pointing at RFC 9728
metadata; RFC 9728 §3.3: the `resource` value must match the URL the
metadata is served from; RFC 8414 §3.3: `issuer` must equal the URL the
metadata was derived from; RFC 9700 §2.1.1: PKCE with S256.)

Timeline: we plan to publish aggregate results, without naming hosts
below rank 1,000, no earlier than 90 days from this notice
({{SEND_DATE + 90 days}}). If you would like quicknode.com removed from the
released dataset entirely, reply to this address or to
{{optout_email}} and we will do so, no questions asked.

Questions, corrections (including "this is intentional"), or a different
contact for future notices are welcome at {{contact_email}}. Project page:
{{project_url}}.

Thank you,
{{sender_name}}
{{institution}}
