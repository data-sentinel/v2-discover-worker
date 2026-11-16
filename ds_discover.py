# ds_discover.py - Data Sentinel discovery worker, Vantage (V2)
#
# Walks a data source and hands in what it finds, for one run's discovery queue at a time.
# Built to WORKER-STANDARD 2026-46-06 (conductor 2026.47.3) and to the queue worker
# contract (architect 2026-46-71). Signs in only through ds_connect_lib.
#
# Layout of this file
#   1  settings            one Settings class, read once; a value that can't be used exits 2
#   2  logs                one format; ids, codes and counts only
#   3  reasons and health  code + params + one English sentence
#   4  the database        two links, named-parameter calls, refusals matched on the HINT
#   5  the contract        the functions this worker calls, checked at start and after a break
#   6  walkers             the interface each source type's walk implements, and the registry
#   7  the hand-in buffer  batches, parents first, and the low-water checkpoint
#   8  the claim           one queue: renew, walk, hand in, then complete or release
#   9  the service         check-in, heartbeat, contract checks, reconnects, resume
#  10  endpoints           /health /ready /status /run /stop
#  11  main                uvicorn, SIGTERM
#      the walks           walk_directory.py, walk_postgres.py, ... (one module a family)
#
#__version__ = '2026.47.1'   # first hand-off: the service, the queue half, the hand-in, directory and postgres (steps 2-7)
#__version__ = '2026.47.2'   # architect 2026-47-01 (unlisted schemas, birth times, no retry on permission denied, the run's count); settings read as the conductor reads them
__version__ = '2026.47.2'

import asyncio
import json
import logging
import os
import signal
import ssl
import sys
import tempfile
import threading
import time
from collections import deque
from datetime import datetime, timezone

import asyncpg
from quart import Quart, jsonify, request

import ds_connect_lib as dcl

WORKER_TYPE = "discover"
STAGE = "discover"

RENEW_SEC = 30               # the contract: renew every 30 seconds
CONTRACT_SEC = 60            # the standard: contract checked every 60 seconds
CONTRACT_AFTER_BREAK = (5, 15, 30)
RECONNECT_MAX_SEC = 30
PING_SEC = 5
RECONCILE_SEC = 60           # an idle worker asks what it holds, so a claim whose answer was lost is picked up
CLAIM_CALL_SEC = 4.0         # /run answers within 5 seconds
SIGTERM_GRACE_SEC = 30       # the standard: running work gets up to 30 seconds
HANDIN_CALL_SEC = 180
HANDIN_REFUSALS_MAX = 3      # an unknown refusal of a hand-in, three times running, is the worker's fault
CHECKPOINT_MAX_CHARS = 8000

log = logging.getLogger("ds_discover")


# =====================================================================================
# 1. Settings
# =====================================================================================
class SettingsError(Exception):
    def __init__(self, variable, why):
        super().__init__(variable + ": " + why)
        self.variable = variable
        self.why = why


def _secret_text(path, name=None):
    """A secret file's value, as the conductor reads it: the platform's files hold {"<name>": "<value>"};
    a file that isn't that is taken as it is, with the line end removed."""
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    key = name or os.path.basename(path)
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict) and key in obj:
            return str(obj[key])
    except ValueError:
        pass
    return raw.strip("\r\n")


def read_database_password(path):
    """The database password: a Docker secret mounted as a file and read as it is. Read at every connect,
    so a rotated secret is picked up by the next one."""
    return _secret_text(path)


class Settings(object):
    """Every setting, read once at start from the environment."""

    def __init__(self, env=None):
        e = os.environ if env is None else env

        def text(name, default=None, required=False):
            v = e.get(name)
            v = v.strip() if isinstance(v, str) else v
            if not v:
                if required:
                    raise SettingsError(name, "is required")
                return default
            return v

        def integer(name, default, lo=None, hi=None):
            raw = text(name)
            if raw is None:
                return default
            try:
                v = int(raw)
            except ValueError:
                raise SettingsError(name, "must be a whole number")
            if (lo is not None and v < lo) or (hi is not None and v > hi):
                raise SettingsError(name, "must be from " + str(lo) + " to " + str(hi))
            return v

        # Who it is, and the repository database: the same names, defaults, secret files and checks as the
        # conductor (WORKER-STANDARD; the conductor's Settings, 2026.47.3). An environment variable wins over
        # the secret file; the files are looked for in DS_SECRETS_DIR.
        self.service = text("DS_SERVICE", "ds_discover")
        self.address = text("DS_SERVICE_EXTERNAL_HOST", self.service)
        self.port = integer("DS_SERVICE_EXTERNAL_PORT", 5600, 1, 65535)
        self.secrets_dir = text("DS_SECRETS_DIR", "/run/secrets")

        def repository(env_name, secret_name, default=None):
            v = text(env_name)
            if v is not None:
                return v
            path = os.path.join(self.secrets_dir, secret_name)
            if os.path.isfile(path):
                try:
                    v = _secret_text(path, secret_name).strip()
                except OSError as exc:
                    raise SettingsError(secret_name, "the secret file " + path + " can't be read ("
                                        + type(exc).__name__ + ")")
                if v:
                    return v
            if default is None:
                raise SettingsError(env_name, "not set, and there is no secret file " + path)
            return default

        self.db_host = repository("DS_DB_HOST", "repository_host")
        port = repository("DS_DB_PORT", "repository_port", "5432")
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise SettingsError("DS_DB_PORT", "'" + port + "' (or the repository_port secret) is not a port number")
        self.db_port = int(port)
        self.db_name = repository("DS_DB_NAME", "repository_name", "data_sentinel")
        self.db_user = repository("DS_DB_USER", "repository_username", "sentinel_worker")
        self.db_password_file = text("DS_DB_PASSWORD_FILE", os.path.join(self.secrets_dir, "sentinel_worker_password"))
        if not os.path.isfile(self.db_password_file):
            raise SettingsError("DS_DB_PASSWORD_FILE", "there is no file " + self.db_password_file)
        try:
            read_database_password(self.db_password_file)
        except OSError as exc:
            raise SettingsError("DS_DB_PASSWORD_FILE", self.db_password_file + " can't be read ("
                                + type(exc).__name__ + ")")
        self.heartbeat_sec = integer("DS_HEARTBEAT_SEC", 30, 1, 110)    # online means a heartbeat under 2 minutes old

        self.log_dir = text("DS_LOG_DIR", "/mnt/logs")
        self.log_level = (text("DS_LOG_LEVEL", "info") or "info").lower()
        if self.log_level not in ("debug", "info", "warning", "error"):
            raise SettingsError("DS_LOG_LEVEL", "must be debug, info, warning or error")

        # Connecting to data sources: as the conductor reads them
        self.file_roots = [r for r in (p.strip() for p in (text("DS_FILE_ROOTS", "") or "").split(":")) if r]
        for r in self.file_roots:
            if not os.path.isabs(r):
                raise SettingsError("DS_FILE_ROOTS", "'" + r + "' is not an absolute path")
        self.ca_bundle = text("DS_CA_BUNDLE")
        if self.ca_bundle and not os.path.isfile(self.ca_bundle):
            raise SettingsError("DS_CA_BUNDLE", "there is no file " + self.ca_bundle)
        self.https_proxy = text("HTTPS_PROXY") or text("https_proxy")
        if self.https_proxy and "://" not in self.https_proxy:
            raise SettingsError("HTTPS_PROXY", "'" + self.https_proxy + "' is not a URL")
        self.no_proxy = text("NO_PROXY") or text("no_proxy") or ""

        self.batch = integer("DS_DISCOVER_BATCH", 10000, 1, 10000)
        self.flush_sec = integer("DS_DISCOVER_FLUSH_SEC", 300, 1, 3600)
        self.threads = integer("DS_DISCOVER_THREADS", None, 1, 64)
        self.statement_sec = integer("DS_DISCOVER_STATEMENT_SEC", 60, 1, 3600)
        self.buffer_max = integer("DS_DISCOVER_BUFFER_MAX", 50000, 1, 10000000)
        if self.buffer_max < self.batch:
            raise SettingsError("DS_DISCOVER_BUFFER_MAX", "must be at least DS_DISCOVER_BATCH")

        # 'directory' owners, with V1's names (ruling 7: the map file and the host's files; no LDAP)
        self.owner_map_file = text("OWNER_MAP_FILE")
        self.owner_map = {}
        if self.owner_map_file:
            try:
                with open(self.owner_map_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
            except (OSError, ValueError):
                raise SettingsError("OWNER_MAP_FILE", "can't be read as JSON")
            if not isinstance(loaded, dict) or any(not isinstance(loaded.get(k, {}), dict)
                                                   for k in ("users", "groups", "sids")):
                raise SettingsError("OWNER_MAP_FILE", "must be an object with users, groups and sids objects")
            self.owner_map = loaded
        self.host_passwd = text("HOST_PASSWD", "/host/etc/passwd")
        self.host_group = text("HOST_GROUP", "/host/etc/group")

    def describe(self):
        """The settings for the start line: no secret, the password file by its path only."""
        return ("service=" + self.service + " address=" + str(self.address) + " port=" + str(self.port)
                + " db=" + str(self.db_host) + ":" + str(self.db_port) + "/" + str(self.db_name)
                + " user=" + str(self.db_user) + " file_roots=" + str(len(self.file_roots))
                + " batch=" + str(self.batch) + " flush_sec=" + str(self.flush_sec)
                + " threads=" + str(self.threads or "per_type") + " statement_sec=" + str(self.statement_sec)
                + " buffer_max=" + str(self.buffer_max) + " ca_bundle=" + ("yes" if self.ca_bundle else "no")
                + " proxy=" + ("yes" if self.https_proxy else "no")
                + " owner_map=" + ("yes" if self.owner_map_file else "no"))

    def proxy(self):
        if not self.https_proxy:
            return None
        return {"https": self.https_proxy, "no_proxy": self.no_proxy or ""}


_CA_FILE = {"path": None}


def ca_file_for(settings):
    """None when no extra authorities are set; otherwise one file with the system's and DS_CA_BUNDLE's,
    written once (the conductor does the same) and passed to connect() as ca_file."""
    if not settings.ca_bundle:
        return None
    if _CA_FILE["path"]:
        return _CA_FILE["path"]
    system = None
    for p in (ssl.get_default_verify_paths().cafile, "/etc/ssl/certs/ca-certificates.crt",
              "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem"):
        if p and os.path.isfile(p):
            system = p
            break
    fd, path = tempfile.mkstemp(prefix="ds_discover_ca_", suffix=".pem")
    with os.fdopen(fd, "w", encoding="utf-8") as out:
        if system:
            with open(system, "r", encoding="utf-8") as f:
                out.write(f.read().rstrip("\n") + "\n")
        with open(settings.ca_bundle, "r", encoding="utf-8") as f:
            out.write(f.read())
    _CA_FILE["path"] = path
    return path


# =====================================================================================
# 2. Logs
# =====================================================================================
class _NoTraceback(logging.Formatter):
    """The standard's format. A record carrying an exception (ours never do; a library's may) gets the
    exception's class instead of its traceback and its text."""

    def format(self, record):
        exc = record.exc_info
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        line = super().format(record)
        if exc and exc[0] is not None:
            line += " (" + exc[0].__name__ + ")"
        return line.splitlines()[0] if line else line


def setup_logging(settings):
    fmt = _NoTraceback("%(asctime)s|%(levelname)s|%(message)s")
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    out = logging.StreamHandler(sys.stdout)
    out.setFormatter(fmt)
    root.addHandler(out)
    if settings.log_dir and os.path.isdir(settings.log_dir):
        try:
            fh = logging.FileHandler(os.path.join(settings.log_dir, settings.service + ".log"), encoding="utf-8")
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError:
            pass
    root.setLevel(logging.WARNING)
    log.setLevel(getattr(logging, settings.log_level.upper()))
    logging.getLogger("ds_connect_lib").setLevel(logging.WARNING)
    for name in ("quart", "uvicorn", "uvicorn.error", "uvicorn.access", "asyncpg", "hypercorn"):
        logging.getLogger(name).setLevel(logging.WARNING)


def kv(**items):
    """One key=value line: values are ids, codes and counts, never a name or a path."""
    return " ".join(k + "=" + str(v) for k, v in items.items())


def where(exc):
    """An exception as its class and where it happened, never its text or a traceback."""
    tb = exc.__traceback__
    last = None
    while tb is not None:
        last = tb
        tb = tb.tb_next
    place = (last.tb_frame.f_code.co_name + ":" + str(last.tb_lineno)) if last else "?"
    return type(exc).__name__ + "@" + place


# =====================================================================================
# 3. Reasons and the health summary
# =====================================================================================
# Each code is one English sentence, no full stop, 200 characters at most.
REASONS = {
    # the shared ones (03 section 6, directive section 7)
    "unexpected": ("The worker failed unexpectedly: {reason}", ("reason",)),
    "place_unlisted": ("This place couldn't be listed: {reason}", ("reason",)),
    # this worker's own
    "data_source_inactive": ("The data source is inactive", ()),
    "type_not_walked": ("This worker can't walk data sources of type {source_type}", ("source_type",)),
    "path_outside_root_path": ("The path {path} isn't under the data source's folder {root_path}", ("path", "root_path")),
}

HEALTH = {
    "idle": ("work", "Idle", ()),
    "working": ("work", "Working on the {stage} stage of run {run_id}", ("stage", "run_id")),
    "winding_down": ("work", "Finishing up on run {run_id}", ("run_id",)),
    "contract_missing": ("problem", "The database is missing functions this worker needs", ("missing",)),
    "starting": ("problem", "The worker is still starting", ()),
    "reconnecting": ("problem", "The worker is reconnecting to the database", ()),
    "stopping": ("problem", "The worker is stopping", ()),
}


# When each is used: for the JSON this worker keeps current and sends with each hand-off (codes_documents()).
REASONS_WHEN = {
    "unexpected": "a release as retry for the worker's own fault: an exception inside a walk (its class is the "
                  "reason, never its text), or a fault it found, such as run_block_without_filter, "
                  "connection_v1_shaped, walk_incomplete, secret_in_checkpoint, objects_invalid",
    "place_unlisted": "on an element handed in with unlisted: a folder or a schema it found and couldn't list. At "
                      "once for a permission denied; after three tries for a timeout or a lost connection. reason "
                      "is a few words (permission denied, timed out), never a path",
    "data_source_inactive": "a release as retry: sys_get_data_source_connection answered data_source_inactive",
    "type_not_walked": "a release as retry: the run's data source is of a type this image has no walk for",
    "path_outside_root_path": "a release as retry: a directory filter's include path is inside the file roots "
                              "but not under the data source's root_path",
}
HEALTH_WHEN = {
    "idle": "holds no queue",
    "working": "holds a queue and is walking it",
    "winding_down": "told to stop, pause or cancel, or SIGTERM: handing in the buffer before letting go",
    "contract_missing": "the contract check found functions missing or not executable. The names are in "
                        "params.missing, not in the text. Not ready",
    "starting": "checked in, and not yet ready: before the first contract check and the first read of what it holds",
    "reconnecting": "the link to the database broke after check-in. Walks go on into the buffer, up to "
                    "DS_DISCOVER_BUFFER_MAX",
    "stopping": "SIGTERM: the status is stopping",
}


def codes_documents():
    """(health codes, reasons): this worker's own, as the JSON it sends with each hand-off."""
    health = {"version": "discover " + __version__, "worker_type": WORKER_TYPE, "codes": [
        {"key": k, "code": code, "text": t, "params": list(p), "when": HEALTH_WHEN[code]}
        for code, (k, t, p) in HEALTH.items()]}
    reasons = {"version": "discover " + __version__,
               "note": "The reasons this worker sends: its own, below, and every code of ds_connect_lib's catalogue "
                       "(" + dcl.__version__ + ") for a release because the data source, or one place in it, can't "
                       "be reached. One code for one sentence, no full stop, 200 characters at most.",
               "reasons": [{"code": code, "params": list(p), "text": t, "where": REASONS_WHEN[code],
                            "sent_by": "discover"} for code, (t, p) in REASONS.items()]}
    return health, reasons


def _sentence(template, params):
    text = template.format(**{k: ("?" if v is None else v) for k, v in params.items()})
    text = " ".join(text.split()).rstrip(" .")
    return text if len(text) <= 200 else text[:199].rstrip() + "…"


def reason(code, params=None):
    """{"code", "params", "text"} for one of this worker's codes, or one of the library's."""
    params = dict(params or {})
    if code in REASONS:
        template, keys = REASONS[code]
        params = {k: params.get(k) for k in keys}
        return {"code": code, "params": params, "text": _sentence(template, params)}
    return {"code": code, "params": params, "text": dcl.message(code, params)}


def health_item(code, params=None):
    _key, template, keys = HEALTH[code]
    params = dict(params or {})
    shown = {k: params.get(k) for k in keys if k != "missing"}
    if "missing" in keys:
        shown_params = {"missing": list(params.get("missing") or [])}
    else:
        shown_params = shown
    return {"code": code, "params": shown_params, "text": _sentence(template, shown)}


def unexpected(exc_or_class):
    name = exc_or_class if isinstance(exc_or_class, str) else type(exc_or_class).__name__
    return reason("unexpected", {"reason": name})


# =====================================================================================
# 4. The database
# =====================================================================================
class DbGone(Exception):
    """The call didn't get an answer: no link, a dropped link, or a time limit. Its outcome is unknown."""


class ContractBroken(DbGone):
    """The function or a parameter is gone or changed (42883, 3F000, 42501, 42P01): back to the contract check."""


class DbRefusal(Exception):
    """The database answered with an error. Matched on its HINT, never on the message."""

    def __init__(self, sqlstate, hint, detail=None):
        super().__init__(str(sqlstate) + " " + str(hint))
        self.sqlstate = sqlstate
        self.hint = hint
        self.detail = detail


class NotService(Exception):
    """The login isn't the workers' login: log it and exit 1."""


CONTRACT_STATES = {"42883", "3F000", "42501", "42P01"}


def _is_link_error(exc):
    if isinstance(exc, (OSError, ConnectionError, asyncpg.exceptions.InterfaceError)):
        return True
    if isinstance(exc, asyncpg.exceptions.PostgresConnectionError):
        return True
    st = getattr(exc, "sqlstate", None) or ""
    return st.startswith("08") or st in ("57P01", "57P02", "57P03")


def _set_keepalive(con):
    """TCP keepalives on the long-lived link: idle 30 s, interval 10 s, 3 probes."""
    try:
        import socket
        sock = getattr(con, "_transport", None)
        sock = sock.get_extra_info("socket") if sock is not None else None
        if sock is None:
            return
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        for opt, val in (("TCP_KEEPIDLE", 30), ("TCP_KEEPINTVL", 10), ("TCP_KEEPCNT", 3)):
            if hasattr(socket, opt):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, opt), val)
    except Exception:
        pass


class Database(object):
    """Two links: one long-lived connection of the worker's own, and a small pool for the calls."""

    def __init__(self, settings):
        self.s = settings
        self.link = None
        self.pool = None
        self.connected = False
        self.on_contract_broken = None
        self.generation = 0             # goes up by one at every successful connect

    def _kwargs(self):
        return dict(host=self.s.db_host, port=self.s.db_port, database=self.s.db_name, user=self.s.db_user,
                    password=lambda: read_database_password(self.s.db_password_file),
                    statement_cache_size=0,
                    server_settings={"application_name": self.s.service},
                    timeout=10)

    async def connect(self):
        await self.close()
        try:
            self.link = await asyncpg.connect(**self._kwargs())
            _set_keepalive(self.link)
            self.pool = await asyncpg.create_pool(min_size=1, max_size=4, **self._kwargs())
        except asyncpg.PostgresError as e:
            await self.close()
            if getattr(e, "hint", None) == "not_service":
                raise NotService()
            raise DbGone(type(e).__name__)
        except Exception as e:
            await self.close()
            raise DbGone(type(e).__name__)
        self.connected = True
        self.generation += 1

    async def close(self):
        self.connected = False
        link, pool = self.link, self.pool
        self.link = self.pool = None
        if link is not None:
            try:
                await asyncio.wait_for(link.close(), 2)
            except Exception:
                link.terminate()
        if pool is not None:
            try:
                await asyncio.wait_for(pool.close(), 2)
            except Exception:
                pool.terminate()

    def mark_gone(self):
        if self.connected:
            log.warning("database link lost")
        self.connected = False

    async def ping(self):
        if not self.connected or self.link is None:
            raise DbGone("not_connected")
        try:
            await self.link.fetchval("select 1", timeout=PING_SEC)
        except Exception as e:
            self.mark_gone()
            raise DbGone(type(e).__name__)

    async def fetch_catalog(self, sql, *args):
        """A read of pg_catalog for the contract check (not a table of the product)."""
        if not self.connected or self.pool is None:
            raise DbGone("not_connected")
        try:
            async with self.pool.acquire(timeout=10) as con:
                return await con.fetch(sql, *args, timeout=10)
        except asyncpg.PostgresError as e:
            if _is_link_error(e):
                self.mark_gone()
                raise DbGone(type(e).__name__)
            raise DbRefusal(e.sqlstate, getattr(e, "hint", None))
        except Exception as e:
            if _is_link_error(e):
                self.mark_gone()
            raise DbGone(type(e).__name__)

    async def call(self, fn, timeout=10.0, **params):
        """select sentinel.<fn>(name => value, ...): the answer as Python. jsonb values go as JSON text."""
        if not self.connected or self.pool is None:
            raise DbGone("not_connected")
        names = list(params)
        sql = "select sentinel." + fn + "(" + ", ".join(n + " => $" + str(i + 1) for i, n in enumerate(names)) + ")"
        args = [json.dumps(v) if isinstance(v, (dict, list)) else v for v in params.values()]
        try:
            async with self.pool.acquire(timeout=timeout) as con:
                value = await con.fetchval(sql, *args, timeout=timeout)
        except asyncpg.PostgresError as e:
            hint = getattr(e, "hint", None)
            if hint == "not_service":
                raise NotService()
            if _is_link_error(e):
                self.mark_gone()
                raise DbGone(type(e).__name__)
            if e.sqlstate in CONTRACT_STATES:
                if self.on_contract_broken:
                    self.on_contract_broken()
                raise ContractBroken(e.sqlstate)
            raise DbRefusal(e.sqlstate, hint, getattr(e, "detail", None))
        except (asyncio.TimeoutError, TimeoutError):
            raise DbGone("timeout")
        except Exception as e:
            if _is_link_error(e):
                self.mark_gone()
            raise DbGone(type(e).__name__)
        if isinstance(value, str):
            try:
                return json.loads(value)
            except ValueError:
                return value
        return value


# =====================================================================================
# 5. The contract
# =====================================================================================
# The functions this worker calls and the named parameters it sends. Optional ones are looked
# for and used when they're there; never a broken contract when they aren't.
CONTRACT_BASE = {
    "sys_post_worker_checkin": ("v_worker_type", "v_worker_name", "v_worker_version", "v_address", "v_port",
                                "v_capabilities"),
    "sys_post_worker_heartbeat": ("v_worker_id", "v_status"),
}
CONTRACT_JOB = {
    "sys_get_data_source_connection": ("v_data_source_id",),
    "sys_post_partition_claim": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id"),
    "sys_post_partition_renew": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt",
                                 "v_progress", "v_checkpoint"),
    "sys_post_partition_complete": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt",
                                    "v_summary"),
    "sys_post_partition_release": ("v_run_id", "v_stage", "v_partition_id", "v_worker_id", "v_attempt",
                                   "v_outcome", "v_code", "v_params", "v_text"),
    "sys_get_partitions_held": ("v_worker_id",),
    "sys_post_discovered_objects": ("v_run_id", "v_partition_id", "v_worker_id", "v_attempt", "v_objects"),
}
CONTRACT_OPTIONAL = {"sys_post_worker_heartbeat": ("v_health",)}

_CONTRACT_SQL = """
select p.proname, p.proargnames, p.proargmodes, p.pronargs, has_function_privilege(p.oid, 'EXECUTE') as can_run
  from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'sentinel' and p.proname = any($1::text[])
"""


async def check_contract(db):
    """(base_ok, job_ok, missing names, optional present). A name is 'fn', 'fn(v_param)' or 'fn (no execute)'."""
    wanted = dict(CONTRACT_BASE)
    wanted.update(CONTRACT_JOB)
    rows = await db.fetch_catalog(_CONTRACT_SQL, list(wanted))
    found = {}
    for r in rows:
        names = list(r["proargnames"] or [])
        modes = list(r["proargmodes"] or [])
        if modes:
            names = [n for n, m in zip(names, modes) if m in ("i", "b", "v")]
        entry = found.setdefault(r["proname"], [])
        entry.append((set(names), bool(r["can_run"])))

    def problems(fn, params):
        if fn not in found:
            return [fn]
        best = None
        for names, can_run in found[fn]:
            miss = [fn + "(" + p + ")" for p in params if p not in names]
            if not can_run:
                miss.append(fn + " (no execute)")
            if best is None or len(miss) < len(best):
                best = miss
        return best

    missing_base, missing_job = [], []
    for fn, params in CONTRACT_BASE.items():
        missing_base += problems(fn, params)
    for fn, params in CONTRACT_JOB.items():
        missing_job += problems(fn, params)
    optional = set()
    for fn, params in CONTRACT_OPTIONAL.items():
        for p in params:
            if fn in found and any(p in names for names, _ in found[fn]):
                optional.add(fn + "." + p)
    return (not missing_base, not missing_base and not missing_job, missing_base + missing_job, optional)


# =====================================================================================
# 6. Walkers
# =====================================================================================
class WalkStopped(Exception):
    """Raised at a stop point when the walk has been told to stop. Not an error."""


class WalkAbandoned(WalkStopped):
    """The queue is no longer this worker's: nothing more may be written for it."""


class WalkerFault(Exception):
    """A walker broke a rule of the hand-in (an element without its required keys, a secret in an element)."""


class OutOfReach(Exception):
    """The whole data source, or a path its filter names, can't be walked, for a reason with one of this
    worker's codes. A release as retry, like a ConnectError (which carries the library's codes)."""

    def __init__(self, code, params=None):
        super().__init__(code)
        self.code = code
        self.params = dict(params or {})


class FilterInvalid(Exception):
    """The filter has a value of the wrong shape for its key. The database checks filters, so this is a fault."""


class Unit(object):
    """The largest piece of a walk that can be finished and ticked off: a drive, a mailbox, a schema.
    Units are walked in order of their id, the same order on every attempt."""
    __slots__ = ("id",)

    def __init__(self, unit_id):
        self.id = str(unit_id)

    def __repr__(self):
        return "Unit(" + self.id + ")"


class WalkContext(object):
    """What a walker gets. It runs in a worker thread: everything here is safe to call from one."""

    def __init__(self, claim, source_type, handle, connection, scope, settings, stop_event, handin, secret_keys,
                 opener=None):
        self.run_id = claim.run_id
        self.source_type = source_type
        self.handle = handle
        # the connection's non-secret values (root_path, host, ...): a walker never needs a secret,
        # because the library has signed in already
        self.connection = {k: v for k, v in (connection or {}).items() if k not in set(secret_keys)}
        self.scope = dict(scope or {})
        self.file_roots = list(settings.file_roots)
        self.statement_sec = settings.statement_sec
        self.settings = settings
        self._stop = stop_event
        self._handin = handin
        self._tls = threading.local()
        self._opener = opener

    def stopping(self):
        return self._stop.is_set()

    def wait_stop(self, seconds):
        """True as soon as the walk is told to stop, False after `seconds` without it."""
        return self._stop.wait(seconds)

    def open_handle(self):
        """Another sign-in through the library, with the data source's connection, secrets and all, which the
        walker never sees: for a second walk thread (a database handle is one per thread), or after a
        connection broke. Raises ConnectError with the library's code, as check() would."""
        if self._opener is None:
            raise dcl.ConnectError("unexpected", {"reason": "no_opener"})
        return self._opener()

    def stop_point(self):
        """Call at every point the walk can stop cleanly: after each page of results, between objects."""
        if self._stop.is_set():
            raise WalkStopped()

    def sleep(self, seconds):
        """A pause in the walk (before a retry) that ends at once, with WalkStopped, when the walk is told to stop."""
        if self._stop.wait(max(0.0, float(seconds))):
            raise WalkStopped()

    def emit(self, element):
        """Hand an element to the buffer. Parents before children: emit a container before what is in it."""
        for k in ("key", "name", "obj_type", "obj_subtype"):
            v = element.get(k)
            if not isinstance(v, str) or not v:
                raise WalkerFault("element_without_" + k)
        self._handin.emit(element, getattr(self._tls, "unit", None))

    def unlisted(self, key, name, path, under, obj_type, obj_subtype, code="place_unlisted", params=None,
                 host=None, parent_key=None):
        """A place found and not listable, as its element: everything whose path begins with `under` is spared."""
        r = reason(code, params or {})
        return {"key": key, "parent_key": parent_key, "host": host or self.source_type, "path": path, "name": name,
                "obj_type": obj_type, "obj_subtype": obj_subtype, "bytes": None, "rows": None,
                "created_at": None, "modified_at": None, "accessed_at": None, "owners": [],
                "to_scan": False, "source": {}, "schema": None, "metadata": {},
                "unlisted": {"under": under, "code": r["code"], "params": r["params"], "text": r["text"]}}


class Walker(object):
    """One source type's walk. Subclasses set source_type, by, default_threads, and implement units() and
    walk_unit(). Both run in worker threads and call ctx.stop_point() at every page."""
    source_type = None
    by = "unit"                 # what the checkpoint's units are: "drive_id", "schema", "path"
    default_threads = 1

    def __init__(self, ctx):
        self.ctx = ctx

    def units(self):
        raise NotImplementedError

    def walk_unit(self, unit):
        raise NotImplementedError

    def close(self):
        """After the last walk thread has ended: let go of anything the walker opened itself."""


WALKERS = {}                    # source type -> Walker subclass; filled by the walk modules as they are ported


def register(walker_cls):
    WALKERS[walker_cls.source_type] = walker_cls
    return walker_cls


def walkable_types():
    """The types this image can walk: a walker exists and the library can sign in to it here."""
    try:
        info = dcl.types()
    except Exception:
        info = {}
    return sorted(t for t in WALKERS if t in info and info[t].available)


# =====================================================================================
# 7. The hand-in buffer
# =====================================================================================
class HandIn(object):
    """Elements in walk order, shared by the walk threads (emit) and the event loop (peek, mark_stored).

    A batch is always the front of the buffer, so a parent emitted before its child is handed in
    in the same batch or an earlier one. A unit is finished when its end has been seen and its last
    element is in a stored batch; the checkpoint is the last unit before the first unfinished one,
    with the number of elements the run has handed in up to it, so a resumed claim counts the run."""

    def __init__(self, buffer_max, by, inherited_checkpoint=None):
        self.cv = threading.Condition()
        self.items = deque()            # (seq, element, monotonic time added)
        self.next_seq = 1
        self.stored_through = 0
        self.buffer_max = buffer_max
        self.abandoned = False
        self.by = by
        self.units = []                 # this attempt's units, in order
        self.skipped = 0                # units the inherited checkpoint covered
        self.unit_last_seq = {}         # unit index -> seq of its last element so far
        self.unit_ended = set()
        self.unit_objects = {}          # unit index -> elements emitted
        self.unit_unlisted = {}
        self.low_water = 0              # units [0, low_water) are finished
        self.ticked = []                # units ticked off since the last take_ticked()
        self.inherited = inherited_checkpoint
        self.checkpoint = None          # the newest low-water mark of this attempt
        self.checkpoint_sent = None
        self.handed_in = 0              # stored by this claim
        self.base_handed_in = 0         # handed in up to the inherited checkpoint's mark, by earlier claims
        self.done_objects = 0           # elements of this claim's finished units
        self.last_activity = time.monotonic()

    # ---- set up
    def set_units(self, units, skipped):
        with self.cv:
            self.units = list(units)
            self.skipped = skipped
            n = self.inherited.get("handed_in") if skipped and isinstance(self.inherited, dict) else None
            self.base_handed_in = n if isinstance(n, int) and not isinstance(n, bool) and n >= 0 else 0

    # ---- walk threads
    def emit(self, element, unit_index):
        with self.cv:
            while len(self.items) >= self.buffer_max and not self.abandoned:
                self.cv.wait(0.5)
            if self.abandoned:
                raise WalkAbandoned()
            seq = self.next_seq
            self.next_seq += 1
            self.items.append((seq, element, time.monotonic()))
            if unit_index is not None:
                self.unit_last_seq[unit_index] = seq
                self.unit_objects[unit_index] = self.unit_objects.get(unit_index, 0) + 1
                if "unlisted" in element:
                    self.unit_unlisted[unit_index] = self.unit_unlisted.get(unit_index, 0) + 1
            self.last_activity = time.monotonic()
            self.cv.notify_all()

    def unit_end(self, unit_index):
        with self.cv:
            self.unit_ended.add(unit_index)
            self._advance()

    # ---- event loop
    def pending(self):
        with self.cv:
            return len(self.items)

    def oldest_age(self):
        with self.cv:
            return (time.monotonic() - self.items[0][2]) if self.items else 0.0

    def peek(self, n):
        with self.cv:
            return [(seq, el) for seq, el, _t in list(self.items)[:n]]

    def mark_stored(self, through_seq, count):
        with self.cv:
            while self.items and self.items[0][0] <= through_seq:
                self.items.popleft()
            self.stored_through = max(self.stored_through, through_seq)
            self.handed_in += count
            self.last_activity = time.monotonic()
            self._advance()
            self.cv.notify_all()

    def _advance(self):
        while self.low_water < len(self.units):
            i = self.low_water
            if i not in self.unit_ended or self.unit_last_seq.get(i, 0) > self.stored_through:
                break
            self.low_water += 1
            self.ticked.append(i)
            self.done_objects += self.unit_objects.get(i, 0)
        if self.low_water > 0:
            self.checkpoint = {"v": 1, "by": self.by, "done_through": self.units[self.low_water - 1].id,
                               "handed_in": self.base_handed_in + self.done_objects}

    def take_ticked(self):
        with self.cv:
            out, self.ticked = self.ticked, []
            return [(self.skipped + i + 1, self.unit_objects.get(i, 0), self.unit_unlisted.get(i, 0)) for i in out]

    def checkpoint_unsent(self):
        """The checkpoint to give at the next renewal, or None when it hasn't moved since it was last given."""
        with self.cv:
            cp = self.checkpoint
            if cp is None or cp == self.checkpoint_sent:
                return None
            if len(json.dumps(cp)) > CHECKPOINT_MAX_CHARS:
                return None
            return dict(cp)

    def checkpoint_given(self, cp):
        with self.cv:
            self.checkpoint_sent = cp

    def abandon(self):
        with self.cv:
            self.abandoned = True
            self.items.clear()
            self.cv.notify_all()

    def counts(self):
        with self.cv:
            total = self.skipped + len(self.units)
            return {"units_total": total, "units_done": self.skipped + self.low_water,
                    "handed_in": self.base_handed_in + self.handed_in}

    def all_finished(self):
        with self.cv:
            return self.low_water == len(self.units) and not self.items


def resume_skip(units, checkpoint, by):
    """(units still to walk, how many the checkpoint covered). A checkpoint that doesn't fit is ignored."""
    ordered = sorted(units, key=lambda u: u.id)
    if not isinstance(checkpoint, dict) or checkpoint.get("v") != 1 or checkpoint.get("by") != by:
        return ordered, 0
    mark = checkpoint.get("done_through")
    if not isinstance(mark, str) or not mark:
        return ordered, 0
    rest = [u for u in ordered if u.id > mark]
    return rest, len(ordered) - len(rest)


# =====================================================================================
# 8. The claim: one queue, from claim to complete or release
# =====================================================================================
FILTER_KEYS = ("scope_snapshot",)      # the run block as built (architect 2026-47-01)
_STOP_RANK = {"sigterm": 1, "paused": 2, "stopped": 3, "cancelled": 4, "lost": 9}


class Claim(object):

    def __init__(self, svc, run_id, stage, partition_id, attempt, run_block):
        self.svc = svc
        self.run_id = int(run_id)
        self.stage = stage
        self.partition_id = int(partition_id)
        self.attempt = int(attempt)
        self.run_block = dict(run_block or {})
        self.state = "working"
        self.stop_kind = None
        self.stop_event = threading.Event()
        self.stop_deadline = None
        self.fault = None               # (reason dict) when the walk failed
        self.lost = False
        self.handin = None
        self.walker = None
        self.handle = None
        self.renew_wake = asyncio.Event()
        self.renew_lock = asyncio.Lock()
        self.task = None
        self.renew_task = None
        self.threads_done = False
        self.secrets = []
        self.refusals = 0
        self.started = time.monotonic()
        self._finished = False
        self._fault_lock = threading.Lock()

    # ---- identity
    def ids(self):
        return dict(v_run_id=self.run_id, v_stage=self.stage, v_partition_id=self.partition_id,
                    v_worker_id=self.svc.worker_id, v_attempt=self.attempt)

    def block(self):
        since = time.monotonic() - (self.handin.last_activity if self.handin else self.started)
        out = {"run_id": self.run_id, "stage": self.stage, "partition_id": self.partition_id,
               "attempt": self.attempt, "state": self.state, "seconds_since_progress": int(since)}
        out.update(self.handin.counts() if self.handin else {"units_total": 0, "units_done": 0, "handed_in": 0})
        return out

    def _run_value(self, *names):
        for n in names:
            if n in self.run_block and self.run_block[n] is not None:
                return self.run_block[n]
        ds = self.run_block.get("data_source")
        ds = ds if isinstance(ds, dict) else {}
        for n in names:
            if n in ds and ds[n] is not None:
                return ds[n]
        return None

    # ---- stopping
    def request_stop(self, kind):
        if self.stop_kind is None or _STOP_RANK[kind] > _STOP_RANK[self.stop_kind]:
            if self.stop_kind is None:
                log.info(kv(discover="stop", run=self.run_id, why=kind))
            self.stop_kind = kind
        if kind == "sigterm" and self.stop_deadline is None:
            self.stop_deadline = time.monotonic() + SIGTERM_GRACE_SEC
        self.state = "winding_down"
        self.stop_event.set()

    def mark_lost(self, why):
        if not self.lost:
            log.warning(kv(discover="lost", run=self.run_id, why=why))
        self.lost = True
        self.request_stop("lost")
        if self.handin:
            self.handin.abandon()
        self.renew_wake.set()

    # ---- renew
    def _apply(self, ans):
        if not isinstance(ans, dict) or not ans.get("held"):
            self.mark_lost("not_held")
        elif ans.get("cancel"):
            self.request_stop("cancelled")
        elif ans.get("stop"):
            self.request_stop("stopped")
        elif ans.get("pause"):
            self.request_stop("paused")

    async def renew(self):
        """One renewal, with the progress counts and the checkpoint when it has moved. Raises DbGone."""
        async with self.renew_lock:
            if self.lost or self._finished:
                return None
            cp = self.handin.checkpoint_unsent() if self.handin else None
            if cp is not None and any(s in json.dumps(cp) for s in self.secrets):
                self.handin.checkpoint_given(cp)
                self._record_fault(unexpected("secret_in_checkpoint"), "fault", WalkerFault("secret_in_checkpoint"))
                cp = None
            progress = self.handin.counts() if self.handin else None
            try:
                ans = await self.svc.db.call("sys_post_partition_renew", v_progress=progress, v_checkpoint=cp,
                                             **self.ids())
            except DbRefusal as r:
                if r.hint == "checkpoint_invalid" and cp is not None:
                    log.error(kv(discover="checkpoint_refused", run=self.run_id))
                    self.handin.checkpoint_given(cp)           # don't offer it again
                    ans = await self.svc.db.call("sys_post_partition_renew", v_progress=progress,
                                                 v_checkpoint=None, **self.ids())
                else:
                    raise
            if cp is not None and isinstance(ans, dict) and ans.get("held"):
                self.handin.checkpoint_given(cp)
            self._apply(ans)
            return ans

    async def _renew_loop(self):
        wait = RENEW_SEC
        while not self.lost and not self._finished:
            try:
                await asyncio.wait_for(self.renew_wake.wait(), wait)
            except (asyncio.TimeoutError, TimeoutError):
                pass
            self.renew_wake.clear()
            if self.lost or self._finished:
                return
            try:
                await self.renew()
                wait = RENEW_SEC
            except DbGone:
                wait = 5                                     # keep its place; renew as soon as the link is back
            except DbRefusal as r:
                log.error(kv(discover="renew_refused", run=self.run_id, hint=r.hint))
                wait = RENEW_SEC

    # ---- hand-in
    def _check_no_secret(self, text):
        for s in self.secrets:
            if s in text:
                raise WalkerFault("secret_in_output")

    async def hand_in_once(self):
        """One batch from the front of the buffer. 'stored', 'lost' or 'retry'."""
        items = self.handin.peek(self.svc.s.batch)
        if not items:
            return "stored"
        try:
            await self.renew()
        except DbGone:
            return "retry"
        if self.lost:
            return "lost"
        payload = await asyncio.to_thread(json.dumps, [el for _seq, el in items])
        self._check_no_secret(payload)
        self.state = "handing_in"
        t0 = time.monotonic()
        try:
            ans = await self.svc.db.call("sys_post_discovered_objects", timeout=HANDIN_CALL_SEC,
                                         v_run_id=self.run_id, v_partition_id=self.partition_id,
                                         v_worker_id=self.svc.worker_id, v_attempt=self.attempt,
                                         v_objects=payload)
        except DbGone:
            return "retry"
        except DbRefusal as r:
            if r.hint == "objects_invalid":
                raise WalkerFault("objects_invalid")
            self.refusals += 1
            log.error(kv(discover="handin_refused", run=self.run_id, hint=r.hint, times=self.refusals))
            if self.refusals >= HANDIN_REFUSALS_MAX:
                raise WalkerFault("handin_refused")
            return "retry"
        finally:
            if self.state == "handing_in":
                self.state = "winding_down" if self.stop_kind else "working"
        self.refusals = 0
        if isinstance(ans, dict) and ans.get("stored"):
            self.handin.mark_stored(items[-1][0], len(items))
            log.info("discover run=" + str(self.run_id) + " handin " + kv(
                n=len(items), new=ans.get("new", 0), known=ans.get("known", 0), moved=ans.get("moved", 0),
                ms=int((time.monotonic() - t0) * 1000)))
            for n, objects, unlisted in self.handin.take_ticked():
                total = self.handin.counts()["units_total"]
                log.info("discover run=" + str(self.run_id) + " unit " + kv(n=n, of=total, objects=objects,
                                                                            unlisted=unlisted))
            return "stored"
        if isinstance(ans, dict) and ans.get("why") == "not_held":
            self.mark_lost("not_held")
            return "lost"
        log.error(kv(discover="handin_answer", run=self.run_id))
        raise WalkerFault("handin_answer")

    async def _wait_or_reconnected(self, sec):
        """Wait up to `sec`, and stop waiting the moment the database link has been made again."""
        gen = self.svc.db.generation
        t_end = time.monotonic() + sec
        while time.monotonic() < t_end and not self.lost:
            if self.svc.db.connected and self.svc.db.generation != gen:
                return
            await asyncio.sleep(0.25)

    async def _handin_loop(self):
        backoff = 1.0
        while True:
            if self.lost:
                return
            n = self.handin.pending()
            if n == 0 and self.threads_done:
                for t in self.handin.take_ticked():   # units with no elements of their own
                    log.info("discover run=" + str(self.run_id) + " unit " + kv(n=t[0], of=self.handin.counts()["units_total"],
                                                                                objects=t[1], unlisted=t[2]))
                return
            due = (n >= self.svc.s.batch or (n > 0 and self.handin.oldest_age() >= self.svc.s.flush_sec)
                   or (n > 0 and self.threads_done))
            if self.stop_deadline is not None and time.monotonic() > self.stop_deadline:
                log.warning(kv(discover="grace_over", run=self.run_id, buffered=n))
                return
            if not due:
                await asyncio.sleep(0.2)
                continue
            try:
                result = await self.hand_in_once()
            except WalkerFault as e:
                self._record_fault(unexpected(str(e)), "fault", e)
                return
            if result == "lost":
                return
            if result == "retry":
                log.warning(kv(discover="handin_retry", run=self.run_id, buffered=n, wait=int(backoff)))
                await self._wait_or_reconnected(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX_SEC)
            else:
                backoff = 1.0

    # ---- the walk threads
    def _thread_main(self, state):
        while not self.stop_event.is_set():
            with state["lock"]:
                i = state["next"]
                state["next"] += 1
            if i >= len(state["units"]):
                return
            self.walker.ctx._tls.unit = i
            try:
                self.walker.walk_unit(state["units"][i])
            except WalkStopped:
                return
            except (dcl.ConnectError, OutOfReach) as e:
                self._record_fault(reason(e.code, e.params), "unreachable", e)
                return
            except Exception as e:
                self._record_fault(unexpected(e), "fault", e)
                return
            finally:
                self.walker.ctx._tls.unit = None
            self.handin.unit_end(i)

    def _record_fault(self, why, kind, exc):
        with self._fault_lock:
            if self.fault is None:
                self.fault = why
                log.error(kv(discover=kind, run=self.run_id, code=why["code"], where=where(exc)))
        self.stop_event.set()

    def filter_snapshot(self):
        """The estate's filter from the claim's run block, or None when the block carries none. 01 names it
        scope_snapshot; the conductor's stand-in (2026.47.3) names it filter. The as-built decides; both are read."""
        for name in FILTER_KEYS:
            if name in self.run_block:
                v = self.run_block[name]
                return v if isinstance(v, dict) else ({} if v is None else None)
        return None

    async def _walk(self, source_type, walker_cls, connection, handle, scope):
        checkpoint = self._run_value("checkpoint")
        secret_keys = ()
        info = dcl.types().get(source_type)
        if info is not None:
            secret_keys = info.secret_keys
        self.handin = HandIn(self.svc.s.buffer_max, walker_cls.by, checkpoint)
        settings = self.svc.s

        def opener():
            return dcl.connect(source_type, connection, timeout=dcl.DEFAULT_TIMEOUT_SEC, file_roots=settings.file_roots,
                               ca_file=ca_file_for(settings), proxy=settings.proxy())
        ctx = WalkContext(self, source_type, handle, connection, scope, settings, self.stop_event,
                          self.handin, secret_keys, opener)
        self.walker = walker_cls(ctx)
        handin_task = asyncio.create_task(self._handin_loop())
        try:
            try:
                all_units = await asyncio.to_thread(self.walker.units)
            except WalkStopped:
                all_units = None
            except (dcl.ConnectError, OutOfReach) as e:
                self._record_fault(reason(e.code, e.params), "unreachable", e)
                all_units = None
            except Exception as e:
                self._record_fault(unexpected(e), "fault", e)
                all_units = None
            if all_units is not None:
                units, skipped = resume_skip(all_units, checkpoint, walker_cls.by)
                self.handin.set_units(units, skipped)
                log.info(kv(discover="units", run=self.run_id, total=len(all_units), skipped=skipped,
                            attempt=self.attempt))
                n = max(1, min(self.svc.s.threads or walker_cls.default_threads, max(1, len(units))))
                state = {"lock": threading.Lock(), "next": 0, "units": units}
                loop = asyncio.get_running_loop()
                threads = [loop.run_in_executor(self.svc.executor, self._thread_main, state) for _ in range(n)]
                await asyncio.gather(*threads, return_exceptions=True)
        finally:
            try:
                await asyncio.to_thread(self.walker.close)
            except Exception as e:
                log.warning(kv(discover="walker_close", run=self.run_id, where=where(e)))
            self.threads_done = True
            await handin_task

    # ---- the whole claim
    async def run(self):
        self.renew_task = asyncio.create_task(self._renew_loop())
        try:
            await self._work()
        except NotService:
            self.svc.fatal("not_service")
        except Exception as e:
            log.error(kv(discover="claim_failed", run=self.run_id, where=where(e)))
        finally:
            self._finished = True
            self.renew_wake.set()
            if self.handle is not None:
                h, self.handle = self.handle, None
                await asyncio.to_thread(h.close)
            if self.svc.claim is self:
                self.svc.claim = None
            self.svc.wake()

    async def _work(self):
        source_type = str(self._run_value("source_type") or "")
        data_source_id = self._run_value("data_source_id")
        log.info(kv(discover="claimed", run=self.run_id, partition=self.partition_id, attempt=self.attempt,
                    type=source_type or "?"))
        walker_cls = WALKERS.get(source_type)
        if walker_cls is None:
            return await self._finish_release("retry", reason("type_not_walked", {"source_type": source_type}))
        scope = self.filter_snapshot()
        if scope is None:
            # never walk the whole data source because the filter didn't arrive
            log.error(kv(discover="run_block_without_filter", run=self.run_id))
            return await self._finish_release("retry", unexpected("run_block_without_filter"))

        # the connection, as the database holds it: V2 keys, secrets decrypted
        connection = None
        while connection is None:
            if self.lost or self.stop_kind:
                return await self._finish()
            try:
                connection = await self.svc.db.call("sys_get_data_source_connection", v_data_source_id=data_source_id)
            except DbGone:
                await asyncio.sleep(2)
            except DbRefusal as r:
                if r.hint == "data_source_inactive":
                    return await self._finish_release("retry", reason("data_source_inactive"))
                return await self._finish_release("retry", unexpected(str(r.hint or r.sqlstate)))
        if not isinstance(connection, dict) or _looks_v1(connection):
            log.error(kv(discover="connection_v1_shaped", run=self.run_id, type=source_type))
            return await self._finish_release("retry", unexpected("connection_v1_shaped"))
        info = dcl.types().get(source_type)
        self.secrets = _secret_strings(connection, info.secret_keys if info else ())

        # sign in, through the library only
        try:
            self.handle = await asyncio.to_thread(
                dcl.connect, source_type, connection, timeout=dcl.DEFAULT_TIMEOUT_SEC,
                file_roots=self.svc.s.file_roots, ca_file=ca_file_for(self.svc.s), proxy=self.svc.s.proxy())
        except dcl.ConnectError as e:
            log.warning(kv(discover="connect_failed", run=self.run_id, code=e.code))
            return await self._finish_release("retry", reason(e.code, e.params))
        log.info(kv(discover="connected", run=self.run_id, type=source_type))
        if self.lost or self.stop_kind:
            return await self._finish()

        await self._walk(source_type, walker_cls, connection, self.handle, scope)
        return await self._finish()

    async def _finish(self):
        """After the walk: complete, release, or keep the claim (SIGTERM), by what stopped it."""
        if self.lost:
            return
        kind = self.stop_kind
        if kind in ("cancelled", "stopped", "paused"):
            return await self._finish_release(kind, None)
        if self.fault is not None:
            return await self._finish_release("retry", self.fault)
        if kind == "sigterm":
            await self._final_renew()
            log.info(kv(discover="sigterm_kept", run=self.run_id, buffered=self.handin.pending() if self.handin else 0))
            return
        if self.handin is not None and self.handin.all_finished():
            return await self._finish_complete()
        # the walk ended without finishing and without a reason: the worker's own fault
        return await self._finish_release("retry", unexpected("walk_incomplete"))

    async def _final_renew(self):
        """The renewal before letting go, so the checkpoint the next holder starts from is current."""
        for _ in range(3):
            if self.lost:
                return
            try:
                await self.renew()
                return
            except DbGone:
                if self.stop_deadline is not None and time.monotonic() > self.stop_deadline:
                    return
                await asyncio.sleep(2)
            except DbRefusal:
                return

    async def _until_answered(self, fn, **params):
        """A final call (complete, release): tried until it has an answer, the claim is lost, or SIGTERM's
        time is up. Its outcome decides nothing locally beyond letting go."""
        backoff = 1.0
        while not self.lost:
            try:
                return await self.svc.db.call(fn, **params)
            except DbGone:
                if self.stop_deadline is not None and time.monotonic() > self.stop_deadline:
                    return None
                await self._wait_or_reconnected(backoff)
                backoff = min(backoff * 2, RECONNECT_MAX_SEC)
        return None

    async def _finish_release(self, outcome, why):
        await self._final_renew()
        if self.lost:
            return
        if outcome == "retry":
            code, params, text = why["code"], why["params"], why["text"]
        else:
            code = params = text = None                       # the database writes the reason for these
        async with self.renew_lock:
            ans = await self._until_answered("sys_post_partition_release", v_outcome=outcome, v_code=code,
                                             v_params=params, v_text=text, **self.ids())
            self._finished = True
        log.info(kv(discover="released", run=self.run_id, outcome=outcome, code=code or "-",
                    state=(ans or {}).get("state", "?") if isinstance(ans, dict) else "?"))

    async def _finish_complete(self):
        summary = self.handin.counts()
        for _ in range(5):
            async with self.renew_lock:
                ans = await self._until_answered("sys_post_partition_complete", v_summary=summary, **self.ids())
                if isinstance(ans, dict) and ans.get("done"):
                    self._finished = True
            if not isinstance(ans, dict):
                return
            if ans.get("done"):
                log.info(kv(discover="completed", run=self.run_id, handed_in=summary["handed_in"],
                            units=summary["units_total"]))
                return
            if ans.get("why") == "not_held":
                self.mark_lost("not_held")
                return
            await asyncio.sleep(5)                           # objects_waiting / more_coming: carry on
        log.error(kv(discover="complete_refused", run=self.run_id))


_V1_ONLY_KEYS = {"URL", "AzureTenant", "OAuthClientId", "OAuthClientSecret", "includeChats", "tenantId", "clientId",
                 "clientSecret", "baseUrl", "lakehouseName", "accessToken", "repoId", "certificatetrust", "initStr",
                 "gmailCreds", "keyfilepath", "filepath", "startDate", "endDate", "workspaceId"}


def _looks_v1(connection):
    return any(k in _V1_ONLY_KEYS for k in connection)


def _secret_strings(connection, secret_keys):
    found = set()

    def collect(v):
        if isinstance(v, str):
            found.add(v)
            for line in v.splitlines():
                found.add(line.strip())
        elif isinstance(v, dict):
            for x in v.values():
                collect(x)
        elif isinstance(v, (list, tuple)):
            for x in v:
                collect(x)

    for k in secret_keys:
        collect(connection.get(k))
    return sorted((s for s in found if len(s) >= dcl.SECRET_MIN_CHARS), key=len, reverse=True)


# =====================================================================================
# 9. The service
# =====================================================================================
class Service(object):

    def __init__(self, settings):
        self.s = settings
        self.db = Database(settings)
        self.db.on_contract_broken = self._contract_dirty
        self.worker_id = None
        self.status_word = "starting"
        self.step = "starting"
        self.contract = {"base": False, "job": False, "missing": [], "optional": set(), "checked_at": None}
        self.claim = None
        self.claim_lock = asyncio.Lock()
        self.stopping = False
        self.fatal_reason = None
        self.started_at = datetime.now(timezone.utc)
        self.last_heartbeat = None
        self.health_sent = None
        self.read_work = False
        self.executor = None
        self._wake = asyncio.Event()
        self._task = None
        self._contract_due = 0.0
        self._extra_checks = []
        self._heartbeat_due = 0.0
        self._ping_due = 0.0
        self._reconcile_due = 0.0
        self._broke_at = None
        self._exit_hook = None

    # ---- state
    @property
    def ready(self):
        return (self.db.connected and self.worker_id is not None and self.contract["job"]
                and not self.stopping and self.fatal_reason is None)

    def ready_step(self):
        if self.stopping:
            return "stopping"
        if not self.db.connected:
            return "reconnecting" if self.worker_id is not None else "connecting"
        if not self.contract["base"] or not self.contract["job"]:
            return "contract_missing" if self.contract["checked_at"] else "checking_contract"
        if self.worker_id is None:
            return "checking_in"
        return "ready"

    def health(self):
        if self.ready:
            problem = None
        elif self.stopping:
            problem = health_item("stopping")
        elif self.contract["checked_at"] and (not self.contract["base"] or not self.contract["job"]):
            problem = health_item("contract_missing", {"missing": self.contract["missing"]})
        elif self.worker_id is not None and not self.db.connected:
            problem = health_item("reconnecting")
        else:
            problem = health_item("starting")
        c = self.claim
        if c is None:
            work = health_item("idle")
        elif c.stop_kind:
            work = health_item("winding_down", {"run_id": c.run_id})
        else:
            work = health_item("working", {"stage": c.stage, "run_id": c.run_id})
        return {"ready": self.ready, "problem": problem, "work": work,
                "detail": {"queue": c.block() if c else None,
                           "last_heartbeat": self.last_heartbeat}}

    def status(self):
        return {
            "worker": {"name": self.s.service, "id": self.worker_id, "version": __version__,
                       "connect_lib": dcl.__version__, "status": self.status_word,
                       "started_at": self.started_at.isoformat(), "step": self.ready_step(),
                       "types": walkable_types()},
            "database": {"connected": self.db.connected, "listening": False, "lock": None,
                         "contract": {"ok": self.contract["job"], "missing": self.contract["missing"]},
                         "last_heartbeat": self.last_heartbeat, "health_sent": self.health_sent},
            "queue": self.claim.block() if self.claim else None,
            "health": self.health(),
        }

    def capabilities(self):
        return {"discover": {"types": walkable_types()}}

    def version(self):
        return __version__ + " (connect " + dcl.__version__ + ")"

    def wake(self):
        self._wake.set()

    def fatal(self, why):
        if self.fatal_reason is None:
            self.fatal_reason = why
            log.error(kv(discover="fatal", why=why))
            if self._exit_hook:
                self._exit_hook(1)

    def _contract_dirty(self):
        self._contract_due = 0.0
        self.wake()

    # ---- life
    async def start(self):
        from concurrent.futures import ThreadPoolExecutor
        self.executor = ThreadPoolExecutor(max_workers=64, thread_name_prefix="ds_discover.walk")
        log.info("discover start " + kv(version=__version__, connect=dcl.__version__,
                                        python=sys.version.split()[0]) + " " + self.s.describe())
        self._task = asyncio.create_task(self._supervise())

    async def _supervise(self):
        backoff = 1.0
        first = True
        while self.fatal_reason is None:
            try:
                if not self.db.connected:
                    self.step = "connecting" if first else "reconnecting"
                    try:
                        await self.db.connect()
                    except DbGone:
                        await self._sleep(backoff)
                        backoff = min(backoff * 2, RECONNECT_MAX_SEC)
                        continue
                    backoff = 1.0
                    log.info(kv(discover="db_connected", first=str(first).lower()))
                    if not first:
                        now = time.monotonic()
                        self._extra_checks = [now + d for d in CONTRACT_AFTER_BREAK]
                    first = False
                    await self._after_connect()
                now = time.monotonic()
                if now >= self._contract_due or (self._extra_checks and now >= self._extra_checks[0]):
                    if self._extra_checks and now >= self._extra_checks[0]:
                        self._extra_checks.pop(0)
                    await self._check_contract()
                if self.worker_id is None and self.contract["base"]:
                    await self._checkin()
                if now >= self._heartbeat_due and self.worker_id is not None:
                    await self._heartbeat()
                if now >= self._ping_due:
                    self._ping_due = now + PING_SEC
                    await self.db.ping()
                if (now >= self._reconcile_due and self.contract["job"] and self.worker_id is not None
                        and self.claim is None and not self.stopping):
                    self._reconcile_due = now + RECONCILE_SEC
                    await self._reconcile()
            except NotService:
                self.fatal("not_service")
                return
            except DbGone:
                pass
            except Exception as e:
                log.error(kv(discover="supervise", where=where(e)))
            await self._sleep(1.0)

    async def _sleep(self, sec):
        try:
            await asyncio.wait_for(self._wake.wait(), sec)
        except (asyncio.TimeoutError, TimeoutError):
            pass
        self._wake.clear()

    async def _after_connect(self):
        await self._check_contract()
        if self.contract["base"]:
            if self.worker_id is None:
                await self._checkin()
            await self._heartbeat()
        if self.contract["job"] and self.worker_id is not None:
            await self._reconcile()
            if self.claim is not None:
                self.claim.renew_wake.set()                  # renew at once: signals sent meanwhile are lost

    async def _check_contract(self):
        self._contract_due = time.monotonic() + CONTRACT_SEC
        base, job, missing, optional = await check_contract(self.db)
        changed = missing != self.contract["missing"] or self.contract["checked_at"] is None
        self.contract.update(base=base, job=job, missing=missing, optional=optional,
                             checked_at=datetime.now(timezone.utc).isoformat())
        if changed:
            if missing:
                log.error(kv(discover="contract_missing", n=len(missing)) + " missing=" + ",".join(missing))
            else:
                log.info(kv(discover="contract_ok"))

    async def _checkin(self):
        ans = await self.db.call("sys_post_worker_checkin", v_worker_type=WORKER_TYPE, v_worker_name=self.s.service,
                                 v_worker_version=self.version(), v_address=self.s.address, v_port=self.s.port,
                                 v_capabilities=self.capabilities())
        self.worker_id = int(ans["worker_id"])
        log.info(kv(discover="checked_in", worker_id=self.worker_id, types=",".join(walkable_types()) or "-"))
        self._heartbeat_due = 0.0

    async def _heartbeat(self, again=True):
        self._heartbeat_due = time.monotonic() + self.s.heartbeat_sec
        if self.worker_id is None:
            return
        use_health = "sys_post_worker_heartbeat.v_health" in self.contract["optional"]
        h = self.health() if use_health else None
        try:
            if use_health:
                await self.db.call("sys_post_worker_heartbeat", v_worker_id=self.worker_id, v_status=self.status_word,
                                   v_health=h)
            else:
                await self.db.call("sys_post_worker_heartbeat", v_worker_id=self.worker_id, v_status=self.status_word)
        except DbRefusal as r:
            if r.hint == "worker_not_found" and again:
                log.warning(kv(discover="worker_not_found"))
                self.worker_id = None
                if self.claim is not None:
                    self.claim.renew_wake.set()               # a rebuilt database: the renew will say not held
                await self._checkin()
                return await self._heartbeat(again=False)
            if r.hint == "health_invalid":
                log.error(kv(discover="health_invalid"))
                await self.db.call("sys_post_worker_heartbeat", v_worker_id=self.worker_id, v_status=self.status_word)
                h = None
            else:
                raise
        self.last_heartbeat = datetime.now(timezone.utc).isoformat()
        self.health_sent = h

    async def _reconcile(self):
        """What the database says this worker holds. A held discovery queue it isn't working on is resumed,
        at the same attempt, from its checkpoint: after a restart, or when a claim's answer was lost."""
        held = await self.db.call("sys_get_partitions_held", v_worker_id=self.worker_id)
        if isinstance(held, dict):
            held = held.get("partitions") or [held]
        held = [h for h in (held or []) if isinstance(h, dict)]
        if not self.read_work:
            self.read_work = True
            self.status_word = "active"
            self._heartbeat_due = 0.0
        for h in held:
            if h.get("stage") != STAGE:
                log.warning(kv(discover="held_other_stage", run=h.get("run_id"), stage=h.get("stage")))
                continue
            async with self.claim_lock:
                if self.claim is not None or self.stopping:
                    continue
                log.info(kv(discover="resume", run=h.get("run_id"), attempt=h.get("attempt")))
                self._start_claim(h["run_id"], h["stage"], h.get("partition_id", 1), h["attempt"], h.get("run") or {})

    def _start_claim(self, run_id, stage, partition_id, attempt, run_block):
        c = Claim(self, run_id, stage, partition_id, attempt, run_block)
        self.claim = c
        c.task = asyncio.create_task(c.run())
        return c

    # ---- the queue endpoints
    async def run_request(self, body):
        if not self.ready:
            return 503, {"claimed": False, "why": "not_ready"}
        try:
            run_id = int(body["run_id"])
            stage = str(body["stage"])
            partition_id = int(body.get("partition_id", 1))
        except (KeyError, TypeError, ValueError):
            return 400, {"claimed": False, "why": "bad_request"}
        if stage != STAGE:
            return 400, {"claimed": False, "why": "wrong_stage"}
        if self.claim is not None or self.claim_lock.locked():
            return 409, {"claimed": False, "why": "busy"}
        async with self.claim_lock:
            if self.claim is not None:
                return 409, {"claimed": False, "why": "busy"}
            try:
                ans = await self.db.call("sys_post_partition_claim", timeout=CLAIM_CALL_SEC, v_run_id=run_id,
                                         v_stage=stage, v_partition_id=partition_id, v_worker_id=self.worker_id)
            except DbGone:
                self._reconcile_due = 0.0                    # if the claim went through, the next look finds it
                self.wake()
                return 503, {"claimed": False, "why": "not_ready"}
            except DbRefusal as r:
                return 409, {"claimed": False, "why": r.hint or r.sqlstate}
            if not isinstance(ans, dict) or not ans.get("claimed"):
                return 409, {"claimed": False, "why": (ans or {}).get("why", "refused") if isinstance(ans, dict) else "refused"}
            attempt = int(ans.get("attempt", 1))
            self._start_claim(run_id, stage, partition_id, attempt, ans.get("run") or {})
            return 200, {"claimed": True, "attempt": attempt}

    async def stop_request(self, body):
        c = self.claim
        try:
            same = (c is not None and int(body["run_id"]) == c.run_id and str(body["stage"]) == c.stage
                    and int(body.get("partition_id", 1)) == c.partition_id)
        except (KeyError, TypeError, ValueError):
            same = False
        if not same:
            return 404, {"held": False}
        why = body.get("why")
        if why == "expired":
            c.mark_lost("expired")
        else:
            c.renew_wake.set()                               # renew now; the answer decides
        return 202, {"held": True}

    # ---- SIGTERM
    async def shutdown(self):
        """The standard's SIGTERM: heartbeat stopping, start nothing, give running work up to 30 seconds,
        close the links. A held queue keeps its claim."""
        if self.stopping:
            return
        self.stopping = True
        self.status_word = "stopping"
        log.info(kv(discover="stopping"))
        try:
            await asyncio.wait_for(self._heartbeat(), 5)
        except Exception:
            pass
        c = self.claim
        if c is not None:
            c.request_stop("sigterm")
            try:
                await asyncio.wait_for(asyncio.shield(c.task), SIGTERM_GRACE_SEC + 2)
            except Exception:
                pass
        if self._task is not None:
            self._task.cancel()
        await self.db.close()
        if self.executor is not None:
            self.executor.shutdown(wait=False, cancel_futures=True)
        log.info(kv(discover="stopped"))


# =====================================================================================
# 10. Endpoints
# =====================================================================================
def create_app(settings):
    app = Quart(__name__)
    svc = Service(settings)
    app.config["service"] = svc

    @app.before_serving
    async def _start():
        await svc.start()

    @app.after_serving
    async def _stop():
        await svc.shutdown()

    @app.errorhandler(Exception)
    async def failed(e):
        # never a traceback: the class and where it happened
        code = getattr(e, "code", None)
        if isinstance(code, int) and 400 <= code < 500:
            return jsonify({"error": type(e).__name__}), code
        log.error(kv(discover="endpoint", where=where(e)))
        return jsonify({"error": "internal"}), 500

    @app.get("/health")
    async def health():
        return jsonify({"up": True}), 200

    @app.get("/ready")
    async def ready():
        if svc.ready:
            return jsonify({"ready": True, "step": "ready"}), 200
        return jsonify({"ready": False, "step": svc.ready_step()}), 503

    @app.get("/status")
    async def status():
        return jsonify(svc.status()), 200

    @app.post("/run")
    async def run():
        body = await request.get_json(force=True, silent=True) or {}
        code, answer = await svc.run_request(body)
        return jsonify(answer), code

    @app.post("/stop")
    async def stop():
        body = await request.get_json(force=True, silent=True) or {}
        code, answer = await svc.stop_request(body)
        return jsonify(answer), code

    return app


# =====================================================================================
# 11. main
# =====================================================================================
def main():
    try:
        settings = Settings()
    except SettingsError as e:
        print(time.strftime("%Y-%m-%d %H:%M:%S") + "|ERROR|discover settings " + e.variable + ": " + e.why, flush=True)
        os._exit(2)
    setup_logging(settings)

    import uvicorn

    app = create_app(settings)
    svc = app.config["service"]
    exit_code = {"code": 0}

    class Server(uvicorn.Server):
        """SIGTERM winds the work down first (the standard's four steps), then lets uvicorn stop."""

        def handle_exit(self, sig, frame):
            if self.should_exit:
                self.force_exit = True
                return
            if getattr(self, "_winding", False):
                return
            self._winding = True
            loop = self._ds_loop

            def begin():
                async def wind():
                    try:
                        await asyncio.wait_for(svc.shutdown(), SIGTERM_GRACE_SEC + 5)
                    finally:
                        self.should_exit = True
                asyncio.ensure_future(wind())
            loop.call_soon_threadsafe(begin)

    config = uvicorn.Config(app, host="0.0.0.0", port=settings.port, log_level="warning",
                            access_log=False, lifespan="on")
    server = Server(config)

    def exit_hook(code):
        exit_code["code"] = code
        server.should_exit = True

    svc._exit_hook = exit_hook

    async def serve():
        server._ds_loop = asyncio.get_running_loop()
        await server.serve()

    try:
        asyncio.run(serve())
    except BaseException as e:                                # never a traceback in the log
        if not isinstance(e, (KeyboardInterrupt, SystemExit)):
            log.error(kv(discover="main", where=where(e)))
            exit_code["code"] = exit_code["code"] or 1
    logging.shutdown()
    os._exit(exit_code["code"])


# =====================================================================================
# The walks: each module registers its walker when imported. Imported last, because each uses the
# names above. A walk whose driver isn't in the image still registers; walkable_types() leaves it out.
# =====================================================================================
import walk_directory       # noqa: E402,F401
import walk_postgres        # noqa: E402,F401


if __name__ == "__main__":
    main()
