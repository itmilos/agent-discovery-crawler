# Hosting a canary site (for cooperating domain owners)

Thank you for lending a domain (or a subdomain) to a short measurement study of
how AI agents discover what a website offers. What you host is eight small
static files, nothing executes, nothing is collected from visitors beyond your
normal access log, and the whole thing can come down after the test window
(about two weeks).

## What you receive

A folder named after your domain, e.g. `sites/notes.example.org/`:

```
index.html                       one plain page, says it is part of a study, links the contact address
robots.txt                       allows all fetching; indexing is declined with a noindex header (below)
llms.txt
openapi.json
.well-known/mcp-server-card
.well-known/mcp/server-card.json
.well-known/agent-card.json
.well-known/security.txt         contact address for the study
```

Some folders contain a made-up word or two (a fictitious tool name, a project
"codename"). That is the canary: if an AI agent repeats it, it must have read
the file. Please do not publish those words anywhere else, and do not link the
site from pages search engines index.

## What we need from you

1. Serve the folder as the document root of the (sub)domain over HTTPS.
   `.well-known/mcp-server-card` has no extension; serve it as
   `application/json`, and send `X-Robots-Tag: noindex, nofollow, noarchive`
   on every response so the made-up words never enter a search index
   (snippets below). No redirects to another host.
2. Keep the site up for the test window we agree (we will tell you the dates).
3. Afterwards, send us the access log for that window, or let us read it. We
   need the request path, time, status and user agent, which is the default
   combined log format. Name the file `<your-domain>.log` if the log lines do
   not carry the host name. IP addresses can be masked; we do not use them.
4. Take the folder down whenever you like after the window.

## nginx

```nginx
server {
    listen 443 ssl http2;
    server_name notes.example.org;
    root /srv/canary/notes.example.org;
    access_log /var/log/nginx/notes.example.org.log combined;

    add_header X-Robots-Tag "noindex, nofollow, noarchive" always;
    location = /.well-known/mcp-server-card { default_type application/json; }
    location ~ \.txt$ { default_type text/plain; charset utf-8; }
    location / { try_files $uri $uri/ =404; }
}
```

## Caddy

```
notes.example.org {
    root * /srv/canary/notes.example.org
    file_server
    header X-Robots-Tag "noindex, nofollow, noarchive"
    @card path /.well-known/mcp-server-card
    header @card Content-Type application/json
    log {
        output file /var/log/caddy/notes.example.org.log
    }
}
```

Caddy's JSON log is read as is; the file name is not needed for the host.

## Self-hosting all sites on one VM (what the authors do when a domain owner prefers to delegate DNS)

Point the (sub)domain's A/AAAA record at the study VM and tell us; the VM
runs Caddy with the `Caddyfile` that `canary:plan` writes (one block per
domain, automatic TLS, the header above, one log per domain). Nothing of
yours runs there besides the eight files.

## Static hosts (Cloudflare Pages, Netlify, GitHub Pages)

These work for the files, but most do not give you a per-request access log,
and the study needs one. If that is all you have, tell us: we can still use
the "answer contained the canary" half of the measurement, just not the
"fetched the file" half.

## What we will do

During the window we run a fixed set of questions about your domain through
three commercial AI assistants (via their vendors' APIs with web tools on),
one at a time, and record what they answer and what they fetched from your log. Each question is asked a handful
of times; expect a few dozen requests to your site in total, most of them to
the files above. Nothing is posted, submitted or purchased. Results are
reported per product, not per domain, and your domain is listed in the paper
only as "cooperating domain n" unless you tell us you would like to be named.

Questions: the address in `.well-known/security.txt`.
