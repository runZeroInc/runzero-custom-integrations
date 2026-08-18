"""Run integrations against REAL vendor endpoints, driven by an out-of-git .env.

The fixture harness proves a script parses what a scenario feeds it. It cannot
prove the scenario resembles the vendor: a response shape invented from
documentation is a hypothesis, and only a real controller settles it. These runs
are the other half -- same scanner, same invariants, real endpoint.

Nothing here is hardcoded. An integration is live-tested when, and only when,
the environment carries credentials for it, and the map from environment
variable to CONFIG parameter is *derived from the integration's own CONFIG
block*. The declaration nobody has to maintain is the one that already exists;
`<slug>/tests/live.json` exists only to say what CONFIG cannot -- a shorter env
prefix, an alias, an invariant this integration legitimately violates.

Entry point: tests/run_live.py. Deliberately not reachable from tests/run.py,
because a test that calls a customer's production controller must never run
because someone typed the wrong command.
"""

import ast
import collections
import difflib
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile

from . import invariants
from .runner import INTEGRATION_ID, read_assets

# A live endpoint is not a fixture server: a full estate walk with N+1
# enrichment can run for minutes, and failing it at the fixture harness's 180s
# would report a defect that is really just a big tenant.
DEFAULT_TIMEOUT = 600

# Suffixes the harness itself owns, so they can never be mistaken for a
# parameter and are rejected as one if an integration ever declares them.
#
# The timeout is LIVE_TIMEOUT rather than TIMEOUT because four integrations
# (linux-ssh among them) declare a `timeout` parameter of their own that means
# something entirely different -- how long to wait on the vendor. The parameter
# the integration sends to the endpoint must win the plain name.
RESERVED_SUFFIXES = ("EXPECT", "EXPECT_FILE", "LIVE_TIMEOUT")

# Redact on the parameter's NAME, not on what the value looks like. CONFIG marks
# most credentials `type: "secret"`, but option-set parameters pulled in through
# `includes` are not visible here at all, so the name pattern is what covers
# tls_client_key and friends. Under-redaction writes a customer's token into a
# terminal and a CI record, so the words are matched generously --
SECRET_WORD_RE = re.compile(r"(password|passwd|secret|token|credential|key)", re.I)

# -- and then narrowed, because over-redaction has its own cost. `auth_url`,
# `auth_scheme` and `key_name` are not credentials, and replacing the endpoint
# URL or the literal "Bearer" with *** throughout the log destroys exactly the
# lines a failing run is read for. An identifier is not the credential it names.
NOT_SECRET_SUFFIX_RE = re.compile(r"_(id|name|url|scheme|header|type|mode)$", re.I)


def looks_secret(name):
    """Whether a parameter name reads as a credential rather than a label."""
    return bool(SECRET_WORD_RE.search(name)) and not NOT_SECRET_SUFFIX_RE.search(name)


# The platform joins a multi-value field with a tab (hostnames, ipAddresses,
# macAddresses, macPairs, tags). Anything comma-joined inside a single value is
# the script's own formatting, not a field boundary -- match those with `~`.
MULTIVALUE_SEPARATOR = "\t"

OPTION_SET_IDENTIFIERS = ("OPTIONS_TLS", "OPTIONS_HTTP")

# The shared option sets `includes` expands, mirrored from
# runzero/custom_integration_config.go:predefinedIntegrationOptionSets. Kept
# here so the generated .env template can name the real variables rather than
# gesturing at a prefix. Recognition itself stays prefix-based (param_for), so a
# new platform option works without editing this table.
OPTION_SETS = {
    "OPTIONS_TLS": [
        {"key": "disable_validation", "label": "Disable TLS validation",
         "type": "bool", "default": False},
        {"key": "ca_cert", "label": "Additional CA certs (PEM)", "type": "textarea"},
        {"key": "peer_hash", "label": "Pinned peer cert SHA-256", "type": "string"},
        {"key": "client_cert", "label": "Client certificate (PEM)", "type": "textarea"},
        {"key": "client_key", "label": "Client key (PEM)", "type": "secret"},
    ],
    "OPTIONS_HTTP": [
        {"key": "user_agent", "label": "User-Agent", "type": "string", "default": ""},
    ],
}

SKIP_DIRS = ("boilerplate", "docs", "scripts", "tests")

# One resolved parameter: what to send, whether to redact it, and the variable
# it came from so a failure can name the thing the developer actually typed.
Value = collections.namedtuple("Value", "value secret env")


class LiveError(Exception):
    """A harness or configuration fault: bad .env, missing CLI, prefix clash."""


class ExpectError(Exception):
    """A term the expectation language does not define.

    Raised rather than skipped. An expectation with a typo that silently passes
    is worse than no expectation at all: it reports a green run for an assertion
    nobody is actually making.
    """


# --------------------------------------------------------------------------
# .env
# --------------------------------------------------------------------------

def load_dotenv(path, environ=None):
    """Apply KEY=VALUE lines from `path` without overriding the real environment.

    Existing environment wins, so `UNIFI_API_KEY=... python3 tests/run_live.py`
    overrides the file for one run and CI can inject secrets from its own vault
    without writing them to disk at all.

    Inline `#` comments are NOT stripped from a value. A password may contain a
    `#`, and quietly truncating a credential at one produces an authentication
    failure that looks like a broken integration.
    """
    environ = os.environ if environ is None else environ
    if not os.path.exists(path):
        return {}
    applied = {}
    with open(path) as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].lstrip()
            if "=" not in line:
                raise LiveError("%s:%d: expected KEY=VALUE, got %r"
                                % (path, lineno, line[:40]))
            key, value = line.split("=", 1)
            key = key.strip()
            if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
                raise LiveError("%s:%d: %r is not a valid variable name"
                                % (path, lineno, key[:40]))
            value = value.strip()
            quote = value[0] if len(value) >= 2 and value[0] == value[-1] \
                and value[0] in "\"'" else ""
            if quote:
                value = value[1:-1]
            if quote == '"':
                value = (value.replace("\\n", "\n").replace("\\t", "\t")
                         .replace('\\"', '"').replace("\\\\", "\\"))
            if key in environ:
                continue
            environ[key] = value
            applied[key] = value
    return applied


def cli_path(environ=None):
    """Resolve RUNZERO_CLI, defaulting to `runzero` on PATH."""
    environ = os.environ if environ is None else environ
    wanted = (environ.get("RUNZERO_CLI") or "").strip() or "runzero"
    found = wanted if os.path.sep in wanted else shutil.which(wanted)
    if not found or not os.path.exists(found):
        raise LiveError("RUNZERO_CLI=%r not found. Set RUNZERO_CLI in .env to a "
                        "runzero binary, or put one on PATH." % wanted)
    if not os.access(found, os.X_OK):
        raise LiveError("RUNZERO_CLI=%r is not executable" % found)
    # /usr/local/bin/runzero ships as a zero-byte placeholder on some installs;
    # exec'ing it fails with an error nobody connects to this cause.
    if os.path.getsize(found) == 0:
        raise LiveError("RUNZERO_CLI=%r is a zero-byte stub, not a scanner" % found)
    return found


# --------------------------------------------------------------------------
# CONFIG
# --------------------------------------------------------------------------

def _matching_brace(text, open_idx):
    depth, quote, escape = 0, None, False
    for idx in range(open_idx, len(text)):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def load_config(script_path):
    """Read the embedded CONFIG dict out of a .star file.

    CONFIG is required to be all literals, so it parses as a Python literal once
    the allowlisted option-set identifiers are quoted. `includes` keeps its
    prefix keys, which is what lets a `tls_`-prefixed environment variable be
    recognised without this harness knowing what OPTIONS_TLS contains.
    """
    with open(script_path) as handle:
        text = handle.read()
    idx = text.find("CONFIG")
    if idx == -1:
        return {}
    equals = text.find("=", idx + len("CONFIG"))
    open_idx = text.find("{", equals)
    if equals == -1 or open_idx == -1:
        return {}
    close_idx = _matching_brace(text, open_idx)
    if close_idx == -1:
        return {}
    literal = text[open_idx:close_idx + 1]
    for identifier in OPTION_SET_IDENTIFIERS:
        literal = literal.replace(identifier, repr(identifier))
    try:
        parsed = ast.literal_eval(literal)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


# --------------------------------------------------------------------------
# Integrations
# --------------------------------------------------------------------------

def default_prefix(slug):
    """UBIQUITI_UNIFI_NETWORK from ubiquiti-unifi-network."""
    return re.sub(r"[^A-Z0-9]+", "_", slug.upper()).strip("_")


class Integration(object):
    """One integration's live-test wiring, derived from CONFIG plus live.json."""

    def __init__(self, slug, script, config, live, ambiguous_scripts=()):
        self.slug = slug
        self.script = script
        self.config = config
        self.live = live
        self.ambiguous_scripts = list(ambiguous_scripts)
        self.prefix = live.get("env_prefix") or default_prefix(slug)
        self.timeout = int(live.get("timeout") or DEFAULT_TIMEOUT)
        self.invariant_skips = list((live.get("invariants") or {}).get("skip", []))

        # Suffix -> CONFIG parameter key. The suffix is the parameter key
        # upper-cased, so `api_key` is <PREFIX>_API_KEY with nothing to declare.
        self.params = {}
        self.required = []
        self.secrets = set()
        for param in config.get("params") or []:
            key = param.get("key") if isinstance(param, dict) else None
            if not isinstance(key, str) or not key:
                continue
            suffix = key.upper()
            self.params[suffix] = key
            if param.get("required"):
                self.required.append(suffix)
            if param.get("type") == "secret" or param.get("secret") \
                    or looks_secret(key):
                self.secrets.add(suffix)

        # `includes` expands a shared option set under a prefix, and those keys
        # are not listed in `params`, so match them by prefix instead: a
        # TLS_DISABLE_VALIDATION suffix maps to tls_disable_validation.
        includes = config.get("includes") or {}
        self.include_prefixes = sorted(k for k in includes if isinstance(k, str))
        self.include_params = []
        for prefix in self.include_prefixes:
            for param in OPTION_SETS.get(includes.get(prefix), []):
                merged = dict(param, key=prefix + param["key"])
                self.include_params.append(merged)
                if merged["type"] == "secret" or looks_secret(merged["key"]):
                    self.secrets.add(merged["key"].upper())

        for suffix, param in (live.get("aliases") or {}).items():
            self.params[suffix.upper()] = param
            if looks_secret(param):
                self.secrets.add(suffix.upper())
        for suffix in live.get("secrets") or []:
            self.secrets.add(suffix.upper())

        for suffix in RESERVED_SUFFIXES:
            if suffix in self.params:
                raise LiveError(
                    "%s: parameter %r collides with the reserved %s_%s variable"
                    % (slug, self.params[suffix], self.prefix, suffix))

    def env_name(self, suffix):
        return "%s_%s" % (self.prefix, suffix)

    def param_for(self, suffix):
        """Map an env suffix to a CONFIG parameter key, or None if unknown."""
        if suffix in self.params:
            return self.params[suffix]
        lowered = suffix.lower()
        for prefix in self.include_prefixes:
            if lowered.startswith(prefix) and len(lowered) > len(prefix):
                return lowered
        return None

    def accepted_suffixes(self):
        """Every suffix this integration answers to."""
        return sorted(set(list(self.params)
                          + [p["key"].upper() for p in self.include_params]
                          + list(RESERVED_SUFFIXES)))

    def accepted(self):
        """Every variable name this integration answers to, for error messages."""
        return [self.env_name(s) for s in self.accepted_suffixes()]

    def is_secret(self, suffix):
        return suffix in self.secrets or looks_secret(suffix)


def discover(repo_root):
    """Every integration directory that ships a script, with its live wiring."""
    found = []
    for slug in sorted(os.listdir(repo_root)):
        directory = os.path.join(repo_root, slug)
        if slug in SKIP_DIRS or slug.startswith(".") or not os.path.isdir(directory):
            continue
        scripts = sorted(glob.glob(os.path.join(directory, "*.star")))
        if not scripts:
            continue
        live_path = os.path.join(directory, "tests", "live.json")
        declared = {}
        if os.path.exists(live_path):
            with open(live_path) as handle:
                try:
                    declared = json.load(handle)
                except ValueError as exc:
                    raise LiveError("%s is not valid JSON: %s" % (live_path, exc))
        # A directory may ship several scripts (API versions). Default to
        # <slug>/<slug>.star, fall back to the only script present, and make a
        # multi-script directory name the one it means in live.json rather than
        # silently testing whichever sorted last.
        preferred = os.path.join(directory, slug + ".star")
        ambiguous = []
        if declared.get("script"):
            script = os.path.join(repo_root, declared["script"])
            if not os.path.exists(script):
                raise LiveError("%s names a script that does not exist: %s"
                                % (live_path, script))
        elif preferred in scripts:
            script = preferred
        elif len(scripts) == 1:
            script = scripts[0]
        else:
            script, ambiguous = None, [os.path.relpath(s, repo_root) for s in scripts]
        config = load_config(script) if script else {}
        found.append(Integration(slug, script, config, declared, ambiguous))

    prefixes = {}
    for integration in found:
        if integration.prefix in prefixes:
            raise LiveError("%s and %s both claim the env prefix %s"
                            % (prefixes[integration.prefix], integration.slug,
                               integration.prefix))
        prefixes[integration.prefix] = integration.slug
    # An env prefix that is a prefix of another makes UNIFI_NETWORK_URL ambiguous
    # between UNIFI and UNIFI_NETWORK, and one of the two loses silently. Refuse
    # the whole run instead of guessing.
    for prefix, slug in sorted(prefixes.items()):
        for other, other_slug in sorted(prefixes.items()):
            if other != prefix and other.startswith(prefix + "_"):
                raise LiveError(
                    "env prefix %s (%s) is a prefix of %s (%s), so variables "
                    "would be ambiguous. Set a distinct env_prefix in "
                    "%s/tests/live.json." % (prefix, slug, other, other_slug, slug))
    return found


# --------------------------------------------------------------------------
# Planning: which integrations are configured, and are they configured fully
# --------------------------------------------------------------------------

class Plan(object):
    """What the harness decided to do with one integration, and why."""

    SKIP = "skip"
    RUN = "run"
    ERROR = "error"

    def __init__(self, integration, state, values=None, expect=None,
                 problems=None, timeout=DEFAULT_TIMEOUT):
        self.integration = integration
        self.state = state
        self.values = values or {}
        self.expect = expect or []
        self.problems = problems or []
        self.timeout = timeout


def plan_for(integration, environ=None):
    """Decide whether to run `integration`, from the environment alone."""
    environ = os.environ if environ is None else environ
    prefix = integration.prefix + "_"
    present = {k[len(prefix):]: v for k, v in environ.items()
               if k.startswith(prefix) and v != ""}
    if not present:
        return Plan(integration, Plan.SKIP)

    problems = []
    if integration.script is None:
        problems.append(
            "%s ships %d scripts; name the one to test with \"script\" in "
            "%s/tests/live.json" % (integration.slug,
                                    len(integration.ambiguous_scripts),
                                    integration.slug))

    # A variable that matches the prefix but no parameter is almost always a
    # typo, and ignoring it silently is how a credential goes unused while the
    # run still reports green.
    values, unknown = {}, []
    for suffix, value in sorted(present.items()):
        if suffix in RESERVED_SUFFIXES:
            continue
        param = integration.param_for(suffix)
        if param is None:
            unknown.append(suffix)
            continue
        # An alias and the parameter it aliases can both be set -- UNIFI_TLS_
        # INSECURE and UNIFI_TLS_DISABLE_VALIDATION are the same switch. Letting
        # the alphabetically later one win would make the run depend on a
        # detail nobody would think to check.
        if param in values:
            problems.append("%s and %s both set the %s parameter; keep one"
                            % (values[param].env, prefix + suffix, param))
        values[param] = Value(value, integration.is_secret(suffix),
                              prefix + suffix)
    if unknown:
        # Match on the suffix, not the whole name: every candidate shares the
        # prefix, and that common head inflates the similarity of every pair
        # until PASSWORD "looks like" URL.
        suffixes = integration.accepted_suffixes()
        for suffix in unknown:
            close = difflib.get_close_matches(suffix, suffixes, 1, 0.7)
            hint = " Did you mean %s%s?" % (prefix, close[0]) if close else ""
            problems.append("%s%s is not a parameter of %s.%s"
                            % (prefix, suffix, integration.slug, hint))
        problems.append("%s accepts: %s"
                        % (integration.slug, ", ".join(integration.accepted())))

    for suffix in integration.required:
        if suffix not in present:
            problems.append("%s%s is required by this integration's CONFIG but "
                            "is not set" % (prefix, suffix))

    # Two ways `--kwargs key=value` corrupts a value in silence, both verified
    # against the scanner. Refuse the run rather than authenticate with half a
    # credential and blame the integration for the 401.
    for value in sorted(values.values(), key=lambda v: v.env):
        raw = value.value
        if "=" in raw and ("," in raw or '"' in raw):
            # pflag re-parses a pair holding more than one "=" with a CSV
            # reader: `filter=a=b,c=d` arrives as filter="a=b" plus an invented
            # parameter c="d", which a CONFIG integration then rejects as
            # unknown -- an error naming a parameter nobody set.
            problems.append(
                "the value of %s cannot be passed through `runzero script "
                "--kwargs`: a value holding \"=\" together with \",\" or a "
                "quote is re-parsed as CSV, so it is cut at the comma and the "
                "remainder becomes a phantom parameter" % value.env)
        elif raw.rstrip('"') != raw:
            # With a single "=" pflag trims quotes off the whole pair, which
            # eats a value's trailing quote. A password ending in " arrives one
            # character short.
            problems.append(
                "the value of %s ends with a quote, which `runzero script "
                "--kwargs` strips: the script would receive it one character "
                "short" % value.env)

    expect_text = present.get("EXPECT", "")
    expect_file = present.get("EXPECT_FILE", "")
    if expect_file:
        if not os.path.exists(expect_file):
            problems.append("%sEXPECT_FILE points at %s, which does not exist"
                            % (prefix, expect_file))
        else:
            expect_text = " ".join(_read_expect_file(expect_file) + [expect_text])
    terms = []
    if not expect_text.strip():
        problems.append("%sEXPECT is not set. A live run with no expectation "
                        "asserts nothing about the estate it just imported."
                        % prefix)
    else:
        try:
            terms = parse_expect(expect_text)
        except ExpectError as exc:
            problems.append(str(exc))

    timeout = integration.timeout
    if present.get("LIVE_TIMEOUT"):
        try:
            timeout = int(present["LIVE_TIMEOUT"])
        except ValueError:
            problems.append("%sLIVE_TIMEOUT=%r is not a whole number of seconds"
                            % (prefix, present["LIVE_TIMEOUT"]))

    for name in integration.invariant_skips:
        if name not in invariants.ALL:
            problems.append("%s/tests/live.json skips unknown invariant %r"
                            % (integration.slug, name))

    state = Plan.ERROR if problems else Plan.RUN
    return Plan(integration, state, values, terms, problems, timeout)


def _read_expect_file(path):
    """One term per line, `#` comments, blank lines ignored."""
    terms = []
    with open(path) as handle:
        for line in handle:
            line = line.strip()
            if line and not line.startswith("#"):
                terms.append(line)
    return terms


# --------------------------------------------------------------------------
# The expectation language
# --------------------------------------------------------------------------

COUNT_FIELDS = ("asset_count", "services", "software", "vulnerabilities")
COUNT_RE = re.compile(r"^(%s)(>=|<=|==|=|>|<)(\d+)$" % "|".join(COUNT_FIELDS))
ANY_RE = re.compile(r"^any:([A-Za-z0-9_.\-]+)(=|~)(.*)$", re.S)
ASSET_RE = re.compile(r"^asset\[(.*)\](?::([A-Za-z0-9_.\-]+)(=|~)(.*))?$", re.S)

GRAMMAR = ("asset_count>=N | services>=N | software>=N | vulnerabilities>=N | "
           "any:<field>=<value> | any:<field>~<substring> | asset[<id>] | "
           "asset[<id>]:<field>=<value>")

COMPARE = {
    ">": lambda got, want: got > want,
    ">=": lambda got, want: got >= want,
    "=": lambda got, want: got == want,
    "==": lambda got, want: got == want,
    "<": lambda got, want: got < want,
    "<=": lambda got, want: got <= want,
}


def parse_expect(text):
    """Parse an expectation string into terms, raising if any term is unknown.

    Terms are whitespace-separated and shell-quoted, so a value with a space is
    written any:os="Windows Server 2019". Every term must parse: an unrecognised
    one fails the run rather than being dropped, and every bad term is reported
    at once so a rewrite is one edit rather than one edit per round trip.
    """
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise ExpectError("could not split the expectation: %s" % exc)
    terms, bad = [], []
    for token in tokens:
        match = COUNT_RE.match(token)
        if match:
            terms.append({"kind": "count", "field": match.group(1),
                          "op": match.group(2), "want": int(match.group(3)),
                          "text": token})
            continue
        match = ANY_RE.match(token)
        if match:
            terms.append({"kind": "any", "field": match.group(1),
                          "op": match.group(2), "want": match.group(3),
                          "text": token})
            continue
        match = ASSET_RE.match(token)
        if match:
            terms.append({"kind": "asset", "id": match.group(1),
                          "field": match.group(2), "op": match.group(3),
                          "want": match.group(4), "text": token})
            continue
        # Collect every bad term rather than stopping at the first. Migrating an
        # expectation written in some other dialect is then one edit instead of
        # one edit per round trip.
        bad.append("cannot parse expectation term %r.%s" % (token, _suggest(token)))
    if bad:
        raise ExpectError("\n        ".join(
            bad + ["Supported terms: %s" % GRAMMAR]))
    return terms


def _suggest(token):
    head = re.split(r"[:=~<>\[]", token, 1)[0]
    if head in ("result_count", "results", "count", "assets", "num_assets",
                "min_assets", "asset_count"):
        return " Did you mean asset_count>=N?"
    if head.startswith("match_"):
        return (" Did you mean any:%s=...? Field names are the ones on the "
                "EMITTED asset (hostnames, ipAddresses, macAddresses, "
                "deviceType, os, or a <prefix>_ custom attribute), not the "
                "vendor's." % head[len("match_"):])
    if "=" in token or "~" in token:
        return " Did you mean any:%s? A field match needs an any: or asset[..]: " \
               "scope." % token
    return ""


def field_values(asset, field):
    """The values of one emitted field, or None when the asset lacks it."""
    raw = asset.get(field)
    if raw is None:
        return None
    if isinstance(raw, list):
        return [str(v) for v in raw]
    return str(raw).split(MULTIVALUE_SEPARATOR)


def _matches(values, raw, op, want):
    if op == "~":
        return want.lower() in str(raw).lower()
    return any(v.strip().lower() == want.strip().lower() for v in values)


def _sample(assets, field, limit=3):
    seen = []
    for asset in assets:
        for value in field_values(asset, field) or []:
            if value and value not in seen:
                seen.append(value)
            if len(seen) >= limit:
                return seen
    return seen


def _field_hint(assets, field):
    """Name the closest field that does exist -- a field typo is the same bug."""
    names = sorted({k for a in assets for k in a})
    close = difflib.get_close_matches(field, names, 3, 0.6)
    if close:
        return ". Closest fields present: %s" % ", ".join(close)
    if names:
        return ". Fields present include: %s" % ", ".join(names[:8])
    return ""


def evaluate(terms, assets):
    """Check parsed terms against the emitted assets. Returns failure strings."""
    failures = []
    totals = {
        "asset_count": len(assets),
        "services": sum(len(invariants._children(a, "_services")) for a in assets),
        "software": sum(len(invariants._children(a, "_software")) for a in assets),
        "vulnerabilities": sum(len(invariants._children(a, "_vulnerabilities"))
                               for a in assets),
    }
    by_id = {a.get("id", ""): a for a in assets}

    for term in terms:
        if term["kind"] == "count":
            got = totals[term["field"]]
            if not COMPARE[term["op"]](got, term["want"]):
                failures.append("%s: got %d" % (term["text"], got))
            continue

        if term["kind"] == "any":
            field = term["field"]
            carriers = [a for a in assets if field_values(a, field) is not None]
            if not carriers:
                failures.append("%s: no asset carries a field named %r%s"
                                % (term["text"], field, _field_hint(assets, field)))
                continue
            if not any(_matches(field_values(a, field), a.get(field),
                                term["op"], term["want"]) for a in carriers):
                failures.append("%s: matched none of %d assets (%s seen: %s)"
                                % (term["text"], len(assets), field,
                                   ", ".join(_sample(assets, field)) or "nothing"))
            continue

        asset = by_id.get(term["id"])
        if asset is None:
            failures.append("%s: no asset with that id (%d assets, e.g. %s)"
                            % (term["text"], len(assets),
                               ", ".join(sorted(by_id)[:3]) or "none"))
            continue
        if term["field"] is None:
            continue
        values = field_values(asset, term["field"])
        if values is None:
            failures.append("%s: that asset has no field %r%s"
                            % (term["text"], term["field"],
                               _field_hint([asset], term["field"])))
            continue
        if not _matches(values, asset.get(term["field"]), term["op"], term["want"]):
            failures.append("%s: that asset's %s is %s"
                            % (term["text"], term["field"],
                               ", ".join(values[:3]) or "empty"))
    return failures


# --------------------------------------------------------------------------
# Redaction
# --------------------------------------------------------------------------

def make_redactor(secrets):
    """Replace every secret value with *** anywhere it appears in output.

    Short secrets are matched only on token boundaries; substring-replacing a
    two-character password would turn the log into confetti and bury the failure
    the log was printed to explain.
    """
    patterns = []
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        if len(secret) >= 4:
            patterns.append(re.escape(secret))
        else:
            patterns.append(r"(?<![A-Za-z0-9])%s(?![A-Za-z0-9])" % re.escape(secret))
    if not patterns:
        return lambda text: text or ""
    compiled = re.compile("|".join(patterns))
    return lambda text: compiled.sub("***", text or "")


# --------------------------------------------------------------------------
# Running
# --------------------------------------------------------------------------

Result = collections.namedtuple("Result", "assets log argv redact timed_out")


def run(plan, cli):
    """Run one planned integration against its real endpoint.

    Nothing returned carries a secret in the clear except `assets`, which is the
    estate the caller asked to import.
    """
    redact = make_redactor(v.value for v in plan.values.values() if v.secret)
    argv = [cli, "script", "--filename", plan.integration.script]
    for param, value in sorted(plan.values.items()):
        # One --kwargs flag per pair. Joining pairs with commas makes any value
        # containing a comma unparseable, which silently drops list-valued
        # parameters and surfaces only as the CLI printing its usage text.
        argv += ["--kwargs", "%s=%s" % (param, value.value)]
    workdir = tempfile.mkdtemp(prefix="rz-live-")
    output = os.path.join(workdir, "scan")
    argv += ["--custom-integration-id", INTEGRATION_ID, "--output", output]
    try:
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=plan.timeout)
        except subprocess.TimeoutExpired:
            return Result(None, "", argv, redact, True)
        except OSError as exc:
            raise LiveError("could not run %s: %s" % (cli, exc))
        log = (proc.stdout or "") + (proc.stderr or "")
        return Result(read_assets(output), log, argv, redact, False)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def command_echo(argv, redact):
    """The command that ran, with every secret replaced before it is printed."""
    return redact(" ".join(shlex.quote(a) for a in argv))
