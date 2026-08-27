"""Run an integration against the real software, in a container.

A fixture scenario proves the script parses what the author *believed* the API
returns. This proves it parses what the software *actually* returns. The
difference is the whole point: a vendor renames a field, wraps a list in an
envelope, or starts returning `null` where the docs promised a string, and a
hand-written fixture keeps passing forever while production breaks.

The tradeoff is honest -- these are slow, need Docker, and only exist for
software that ships a self-hostable image. So they are a separate entry point
(`tests/run_containers.py`) and never run as part of `tests/run.py`.

Everything downstream of "the scanner ran" is shared with the fixture harness:
the export parser, the whole `expect` vocabulary, and the invariants all come
from `runner`/`invariants` rather than being reimplemented here. What this
module adds is only the lifecycle -- allocate a port, compose up, wait for
genuine readiness, seed, run, tear down.
"""

import contextlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from . import invariants
from . import runner

# Manifest keys that only the fixture harness can answer. There is no recording
# proxy in front of the container, so `requests` is always empty here and a
# request assertion would silently pass or confusingly fail. Reject it at load
# time instead of letting the author believe it ran.
REQUEST_ONLY_EXPECT_KEYS = (
    "request_count", "min_requests", "requests_include", "requests_absent",
)

SEED_REF_RE = re.compile(r"\$\{seed\.([A-Za-z0-9_]+)\}")

DEFAULT_READY_TIMEOUT = 600
DEFAULT_READY_INTERVAL = 3
DEFAULT_SEED_TIMEOUT = 600
DEFAULT_LOG_TAIL = 60


class ContainerError(Exception):
    """A lifecycle step failed. The message is shown as the test failure."""


# --- Docker availability -------------------------------------------------

def docker_available():
    """Return (ok, reason). Never raises: an absent Docker is a skip, not a fail."""
    if not shutil.which("docker"):
        return False, "docker is not on PATH"
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "could not run `docker info`: %s" % exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, "`docker info` failed: %s" % (detail[0] if detail else "unknown error")
    try:
        proc = subprocess.run(["docker", "compose", "version"],
                              capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "could not run `docker compose version`: %s" % exc
    if proc.returncode != 0:
        return False, "`docker compose` plugin is not installed"
    return True, ""


# --- Manifest discovery --------------------------------------------------

def find_manifests(repo_root):
    """Every <slug>/tests/docker/manifest.json, sorted."""
    pattern = os.path.join(repo_root, "*", "tests", "docker", "manifest.json")
    import glob as _glob
    return sorted(_glob.glob(pattern))


def load_manifest(path):
    """Read a manifest and fill in the defaults its directory implies."""
    with open(path) as handle:
        manifest = json.load(handle)

    docker_dir = os.path.dirname(os.path.abspath(path))
    # <repo>/<slug>/tests/docker/manifest.json -- the slug is three up.
    slug = manifest.get("integration") or os.path.basename(
        os.path.dirname(os.path.dirname(docker_dir)))

    manifest["_dir"] = docker_dir
    manifest["_slug"] = slug
    manifest["name"] = manifest.get("name") or "container"
    manifest["_label"] = "%s/%s" % (slug, manifest["name"])

    for key in REQUEST_ONLY_EXPECT_KEYS:
        if key in (manifest.get("expect") or {}):
            raise ContainerError(
                "%s: expect.%s is a fixture-only assertion; the container harness "
                "does not proxy requests" % (manifest["_label"], key))
    return manifest


# --- Port allocation -----------------------------------------------------

def free_port():
    """Ask the kernel for an unused TCP port.

    Pinning a port in the compose file makes two integrations -- or two runs --
    collide, and a collision looks exactly like a broken integration. Binding
    :0 and releasing leaves a small race, which is why the caller retries.
    """
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- Compose lifecycle ---------------------------------------------------

def compose_argv(manifest, project):
    compose_file = os.path.join(manifest["_dir"], manifest.get("compose") or "compose.yml")
    if not os.path.exists(compose_file):
        raise ContainerError("no compose file at %s" % compose_file)
    return ["docker", "compose", "-p", project, "-f", compose_file]


def compose_env(manifest, ports):
    """Environment handed to `docker compose`, carrying the allocated ports.

    A compose file refers to these as ${RZ_HOST_PORT} so nothing in the
    repository has to hard-code a port number.
    """
    env = dict(os.environ)
    env["RZ_HOST_PORT"] = str(ports["primary"])
    for name, value in ports.items():
        env["RZ_PORT_" + name.upper()] = str(value)
    return env


def compose_up(manifest, project, ports, timeout):
    argv = compose_argv(manifest, project) + ["up", "-d", "--remove-orphans"]
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=timeout, env=compose_env(manifest, ports))
    if proc.returncode != 0:
        raise ContainerError("compose up failed:\n%s" % _tail(proc.stderr or proc.stdout, 25))


def compose_down(manifest, project, ports):
    """Best effort. Called from a finally block, so it must never raise."""
    try:
        argv = compose_argv(manifest, project) + ["down", "-v", "--remove-orphans", "-t", "5"]
        subprocess.run(argv, capture_output=True, text=True, timeout=300,
                       env=compose_env(manifest, ports))
    except Exception:
        pass


# --- Teardown verification -----------------------------------------------
#
# `compose down` usually works, so it is tempting to trust it. It is exactly
# the cases where it does not -- a container wedged in a restart loop, a
# compose call that itself timed out, a killed test process -- that matter,
# because a leaked container keeps holding its published port and its share of
# the host. The *next* integration then fails with a port collision or an
# out-of-memory kill that looks like its own bug, and the real cause is two
# stacks up at once. So teardown is verified rather than assumed.

COMPOSE_PROJECT_LABEL = "com.docker.compose.project"
PROJECT_PREFIX = "rzci-"

# Every instance of this suite shares PROJECT_PREFIX, so the prefix alone cannot
# tell a corpse an earlier run left behind from a stack a second run is using
# right now. The pid can, and it goes at the front of the name so `docker ps`
# groups a run's stacks together and says out loud whose they are.
RUN_PREFIX = "%s%d-" % (PROJECT_PREFIX, os.getpid())

# Every project this process started, so the end-of-run sweep can tell a leak it
# caused from a stack that belongs to somebody else's run. Only the first is
# force-removed, and only the first is a failure of this run.
STARTED_PROJECTS = []


def _docker(argv, timeout=60):
    """Run a docker command, returning stdout. Never raises."""
    try:
        proc = subprocess.run(["docker"] + list(argv), capture_output=True,
                              text=True, timeout=timeout)
        return proc.stdout or ""
    except Exception:
        return ""


def project_containers(project):
    """Every container -- running or not -- still labelled for this project."""
    out = _docker(["ps", "-a", "--no-trunc",
                   "--filter", "label=%s=%s" % (COMPOSE_PROJECT_LABEL, project),
                   "--format", "{{.ID}} {{.Names}} {{.Image}} {{.Status}}"])
    return [line for line in out.splitlines() if line.strip()]


def started_here(project):
    """Did *this* process start this project?

    The only ownership answer the sweep is allowed to act on. `RUN_PREFIX` makes
    ownership readable in `docker ps`, but a recycled pid can file an earlier
    run's corpse under this run's prefix, and a corpse must not be reported as a
    leak this run caused.
    """
    return project in STARTED_PROJECTS


def stray_projects(exclude=()):
    """Harness-owned compose projects that are still up, other than `exclude`.

    Used as a precondition as well as a postcondition: starting a stack while
    another one is still running is the failure mode this whole module is
    trying to avoid, so it is worth detecting before the new stack adds load
    rather than after.

    Deliberately spans every instance of the suite, not just this one: a second
    run's stack loads the host exactly as much as a leaked one, so a case that
    is about to fail for reasons it did not cause should say so. What the caller
    may *remove* is a narrower question -- see `started_here`.
    """
    label = "{{.Label \"%s\"}}" % COMPOSE_PROJECT_LABEL
    # Networks as well as containers: `compose down` can remove the containers
    # and still leave the network behind, and a stack that pins its subnet
    # cannot start again while the old network holds it.
    out = (_docker(["ps", "-a", "--no-trunc", "--format", label])
           + _docker(["network", "ls", "--format", label]))
    found = set()
    for line in out.splitlines():
        name = line.strip()
        if name.startswith(PROJECT_PREFIX) and name not in exclude:
            found.add(name)
    return sorted(found)


def project_networks(project):
    """Compose networks still labelled for this project."""
    out = _docker(["network", "ls", "--filter",
                   "label=%s=%s" % (COMPOSE_PROJECT_LABEL, project),
                   "--format", "{{.Name}}"])
    return [name for name in out.split() if name.strip()]


def force_remove_project(project):
    """Last resort: `docker rm -f` every container the project still owns.

    Networks go too. A compose network outlives the containers that used it, and
    a surviving one both holds its subnet -- which matters here, because some
    stacks pin theirs -- and keeps the project name looking occupied.
    """
    ids = [line.split()[0] for line in project_containers(project)]
    if ids:
        _docker(["rm", "-f", "--volumes"] + ids, timeout=180)
    nets = project_networks(project)
    if nets:
        _docker(["network", "rm"] + nets, timeout=60)
    return ids


def verify_torn_down(project, on_progress=None):
    """Assert `docker ps` is clean for this project; force-remove what is not.

    Returns a list of warning strings -- empty when teardown was clean. A leak
    is reported loudly rather than silently repaired, because a stack that
    needs `rm -f` to die is a bug in that stack's compose file, and hiding it
    just moves the failure to whoever runs the suite next.
    """
    warnings = []
    survivors = project_containers(project)
    if survivors:
        warnings.append("teardown leaked %d container(s) after `compose down`: %s"
                        % (len(survivors), "; ".join(survivors)))
        removed = force_remove_project(project)
        if on_progress:
            on_progress("      WARN leaked container(s), force-removed %d" % len(removed))
        still = project_containers(project)
        if still:
            warnings.append("STILL RUNNING after `docker rm -f`: %s" % "; ".join(still))
    # Compose also creates a network per project; a dangling one blocks reuse of
    # the project name and signals the containers were not fully released.
    nets = project_networks(project)
    if nets:
        _docker(["network", "rm"] + nets, timeout=60)
    return warnings


def compose_logs(manifest, project, ports, tail=DEFAULT_LOG_TAIL):
    try:
        argv = compose_argv(manifest, project) + ["logs", "--no-color", "--tail", str(tail)]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=120,
                              env=compose_env(manifest, ports))
        return proc.stdout or proc.stderr or ""
    except Exception as exc:
        return "(could not collect logs: %s)" % exc


def compose_exec(manifest, project, ports, service, argv, timeout=120):
    full = compose_argv(manifest, project) + ["exec", "-T", service] + list(argv)
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout,
                          env=compose_env(manifest, ports))


# --- Readiness -----------------------------------------------------------

def _http_probe(url, insecure, expect_status, body_contains, timeout=10):
    """Return (ok, detail). A connection refused is a normal 'not yet'."""
    ctx = None
    if url.startswith("https://") and insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=ctx) as response:
            status, body = response.status, response.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        # A 401 from an API that is up but wants credentials is a perfectly good
        # readiness signal, so the manifest gets to name which codes count.
        status, body = exc.code, exc.read(65536).decode("utf-8", "replace")
    except Exception as exc:
        return False, str(exc)
    if expect_status and status not in expect_status:
        return False, "status %d" % status
    if body_contains and body_contains not in body:
        return False, "status %d, body lacks %r" % (status, body_contains)
    return True, "status %d" % status


def wait_ready(manifest, project, ports, base, gates, on_progress=None):
    """Poll each readiness gate in order until it passes or its deadline expires.

    Gates are ordered because readiness is layered: the HTTP port opens well
    before the database migration finishes, and the API answers `/status` long
    before it will answer `/nodes`. A blind sleep either wastes minutes or
    fails intermittently, so there is deliberately no sleep-based gate here.
    """
    for index, gate in enumerate(gates):
        timeout = gate.get("timeout", DEFAULT_READY_TIMEOUT)
        interval = gate.get("interval", DEFAULT_READY_INTERVAL)
        label = gate.get("name") or "gate %d" % (index + 1)
        deadline = time.time() + timeout
        last = "never attempted"
        while time.time() < deadline:
            ok, last = _run_gate(manifest, project, ports, base, gate)
            if ok:
                if on_progress:
                    on_progress("      ready: %s (%s)" % (label, last))
                break
            time.sleep(interval)
        else:
            raise ContainerError(
                "readiness gate %r did not pass within %ds (last: %s)" % (label, timeout, last))


def _run_gate(manifest, project, ports, base, gate):
    if "http" in gate:
        spec = gate["http"]
        url = runner.substitute(spec.get("url") or (base + spec.get("path", "/")), base)
        return _http_probe(
            url,
            insecure=spec.get("insecure", True),
            expect_status=spec.get("status") or [200],
            body_contains=spec.get("body_contains"),
        )
    if "exec" in gate:
        service = gate.get("service") or manifest.get("service")
        if not service:
            return False, "gate has no service and the manifest declares no default"
        try:
            proc = compose_exec(manifest, project, ports, service, gate["exec"],
                                timeout=gate.get("exec_timeout", 120))
        except subprocess.SubprocessError as exc:
            return False, str(exc)
        output = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode != 0:
            return False, "exit %d: %s" % (proc.returncode, _tail(output, 2))
        if gate.get("contains") and gate["contains"] not in output:
            return False, "output lacks %r" % gate["contains"]
        return True, "exit 0"
    return False, "gate declares neither `http` nor `exec`"


# --- Seeding -------------------------------------------------------------

def run_seed(manifest, project, ports, base, timeout=DEFAULT_SEED_TIMEOUT):
    """Run the integration's seed script and return the dict it printed.

    A test that needs a human to click through a setup wizard is not a test, so
    every containerized integration owns a seed script that creates its admin
    user, its API credential, and at least one device record. The script prints
    a JSON object; manifests reference those values as ${seed.<key>}.
    """
    seed = manifest.get("seed")
    if not seed:
        return {}
    script = os.path.join(manifest["_dir"], seed)
    if not os.path.exists(script):
        raise ContainerError("no seed script at %s" % script)

    env = compose_env(manifest, ports)
    env.update({
        "RZ_BASE": base,
        "RZ_HOST_PORT": str(ports["primary"]),
        "RZ_PROJECT": project,
        "RZ_COMPOSE_FILE": os.path.join(manifest["_dir"], manifest.get("compose") or "compose.yml"),
        "RZ_SERVICE": manifest.get("service") or "",
        "RZ_DOCKER_DIR": manifest["_dir"],
    })
    argv = ["python3", script] if script.endswith(".py") else ["sh", script]
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
    if proc.returncode != 0:
        raise ContainerError("seed script failed (exit %d):\n%s\n%s" % (
            proc.returncode, _tail(proc.stdout, 20), _tail(proc.stderr, 20)))

    lines = [ln for ln in (proc.stdout or "").splitlines() if ln.strip()]
    if not lines:
        return {}
    try:
        parsed = json.loads(lines[-1])
    except ValueError:
        raise ContainerError(
            "seed script must print a JSON object as its last line, got: %s" % _tail(proc.stdout, 5))
    if not isinstance(parsed, dict):
        raise ContainerError("seed script printed %s, expected a JSON object" % type(parsed).__name__)
    return parsed


def expand_seed(value, seed):
    """Replace every ${seed.key} in a JSON blob with the seed script's output."""
    def replace(match):
        key = match.group(1)
        if key not in seed:
            raise ContainerError("manifest references ${seed.%s} but the seed script "
                                 "printed only %s" % (key, sorted(seed)))
        return str(seed[key])
    return SEED_REF_RE.sub(replace, value)


# --- The scanner run -----------------------------------------------------

def run_scanner(script, kwargs, scanner, timeout):
    """Run the scanner against the live container; returns (assets, log, rc).

    Deliberately mirrors `runner.run_once` minus the fixture server: same
    binary, same flags, same export parser, so an integration behaves here
    exactly as it does under `tests/run.py` and in production.
    """
    workdir = tempfile.mkdtemp(prefix="rz-container-")
    output = os.path.join(workdir, "scan")
    try:
        argv = [scanner, "script", "--filename", script]
        for key, value in kwargs.items():
            argv += ["--kwargs", "%s=%s" % (key, value)]
        argv += ["--custom-integration-id", runner.INTEGRATION_ID, "--output", output]
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return (runner.read_assets(output),
                (proc.stdout or "") + (proc.stderr or ""), proc.returncode)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


# --- The test ------------------------------------------------------------

def run_manifest(path, scanner, repo_root, verbose=True):
    """Bring the container up, seed it, run the integration, tear it down.

    Returns (ok, label, [failure, ...]). Teardown is in a finally block: a
    failed assertion must not leave a database container running, or the next
    run collides with it and the failure looks like something else entirely.
    """
    manifest = load_manifest(path)
    label = manifest["_label"]
    slug = manifest["_slug"]

    script = os.path.join(repo_root, manifest.get("script") or os.path.join(slug, slug + ".star"))
    if not os.path.exists(script):
        return False, label, ["no such integration script: %s" % script]

    project = "%s%s-%s" % (RUN_PREFIX, slug.replace("_", "-"), manifest["name"].replace("_", "-"))
    ports = {"primary": free_port()}
    for name, _ in (manifest.get("extra_ports") or {}).items():
        ports[name] = free_port()
    scheme = manifest.get("scheme", "http")
    base = "%s://127.0.0.1:%d" % (scheme, ports["primary"])

    def log(message):
        if verbose:
            print(message, flush=True)

    failures = []
    try:
        # One stack at a time is the rule the host depends on. If a previous
        # case leaked, say so here -- otherwise this case starts under load it
        # did not create and fails for reasons that have nothing to do with it.
        # A second instance of the suite breaks the same rule and gets the same
        # warning, but is never touched: it is somebody's live run, not litter.
        for stray in stray_projects(exclude=(project,)):
            log("      WARN a harness stack is still up: %s (%s)" % (
                stray, "leaked by this run" if started_here(stray) else "another run's"))

        STARTED_PROJECTS.append(project)
        log("      starting %s" % os.path.basename(manifest.get("compose") or "compose.yml"))
        compose_up(manifest, project, ports, manifest.get("startup_timeout", 900))

        wait_ready(manifest, project, ports, base, manifest.get("ready") or [], on_progress=log)

        seed = run_seed(manifest, project, ports, base,
                        timeout=manifest.get("seed_timeout", DEFAULT_SEED_TIMEOUT))
        if seed:
            log("      seeded: %s" % ", ".join(sorted(seed)))

        # Some software only exposes a seeded record after an async worker picks
        # it up, so a manifest may gate a second time after seeding.
        wait_ready(manifest, project, ports, base, manifest.get("ready_after_seed") or [],
                   on_progress=log)

        resolved = json.loads(expand_seed(json.dumps(manifest), seed))
        kwargs = {k: runner.substitute(v, base) for k, v in (resolved.get("kwargs") or {}).items()}

        # Same trap the fixture harness guards: --kwargs is a stringToString flag
        # that splits on commas *inside* one flag's value, so `ids=1,2` arrives as
        # ids="1" plus a fabricated parameter 2="". Worth checking again here
        # because a value can arrive from the seed script rather than the
        # manifest, and a generated token is exactly the kind of thing nobody
        # thinks to check for commas.
        comma_kwargs = sorted(k for k, v in kwargs.items() if "," in str(v))
        if comma_kwargs:
            raise ContainerError(
                "kwarg(s) %s contain a comma; the runZero CLI splits each into a "
                "second parameter, so this case cannot test what it declares"
                % ", ".join(repr(k) for k in comma_kwargs))

        assets, run_log, rc = run_scanner(script, kwargs, scanner, manifest.get("timeout", 600))
        log("      scanner emitted %d asset(s)" % len(assets))

        # The whole `expect` vocabulary and every invariant come from the fixture
        # harness. `requests` is empty because there is no proxy in front of the
        # container; request assertions are rejected at manifest load.
        failures += runner.check_expectations(resolved, assets, [], run_log, base, None, rc)

        skip = set((resolved.get("invariants") or {}).get("skip") or [])
        for name, message in invariants.run(assets, skip):
            failures.append("invariant %s: %s" % (name, message))

        if resolved.get("check_determinism", True):
            again = run_scanner(script, kwargs, scanner, manifest.get("timeout", 600))[0]
            first = sorted(a.get("id", "") for a in assets)
            second = sorted(a.get("id", "") for a in again)
            if first != second:
                failures.append("ids are not deterministic across two runs "
                                "against the same container")

        if failures and verbose:
            print("      --- container logs ---", flush=True)
            print(_indent(compose_logs(manifest, project, ports)), flush=True)

    except ContainerError as exc:
        failures.append(str(exc))
        if verbose:
            print("      --- container logs ---", flush=True)
            print(_indent(compose_logs(manifest, project, ports)), flush=True)
    except subprocess.TimeoutExpired as exc:
        failures.append("timed out: %s" % exc)
    except KeyboardInterrupt:
        # Ctrl-C still has to tear the stack down; re-raised after the finally.
        failures.append("interrupted")
        raise
    finally:
        compose_down(manifest, project, ports)
        # A leak is a failure of this case even when every assertion passed:
        # the next case inherits the load, and CI should go red on it.
        leaks = verify_torn_down(project, on_progress=log)
        failures += leaks
        if not leaks:
            log("      torn down, `docker ps` clean for %s" % project)

    return (not failures), label, failures


# --- Small helpers -------------------------------------------------------

def _tail(text, lines):
    if not text:
        return ""
    return "\n".join((text or "").strip().splitlines()[-lines:])


def _indent(text, prefix="        "):
    return "\n".join(prefix + line for line in (text or "").splitlines()[-DEFAULT_LOG_TAIL:])
