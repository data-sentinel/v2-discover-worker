# walk_postgres.py - the 'postgres' walk: the tables of one database, a schema at a time
#
# Port of V1's postgresdb_discovery and table_level_schema_generator (ds_discover_worker.py), on the
# library's psycopg2 connection instead of a SQLAlchemy engine:
#   key      schema.table                       path  the schema        host  the connection's host
#   bytes    pg_total_relation_size: the table with its indexes and TOAST; a partitioned table, its partitions'
#   rows     pg_class.reltuples, the planner's count as of the last ANALYZE; null when never analysed
#   schema   {"columns": [...], "constraints": [...]}: the columns, and the primary, unique and foreign keys
#   source   {"scan_sql": ...}: V1's SELECT of the table's columns, bytea left out, 200 columns at most,
#            identifiers quoted for PostgreSQL (V1 wrote SQL Server's brackets)
#   owners   the table's owner and its schema's owner, as roles
#   units    schemas, by name
#
# Only the catalogue is read: no row of a customer's table. The session is autocommit and read-only, every
# statement has DS_DISCOVER_STATEMENT_SEC, a lock is waited for 5 seconds at most (a size function waits
# behind an ALTER TABLE otherwise, and makes everyone else wait behind it), and the statement running when
# the walk is told to stop is cancelled at once.
import re
import threading

import ds_connect_lib as dcl
import ds_discover as dd

PAGE = 500                          # tables read between two stop points
SCAN_SQL_MAX_COLS = 200             # V1's cap on scan_sql's width
LOCK_TIMEOUT_MS = 5000
PLACE_TRIES = 3
PLACE_RETRY_DELAYS = (2.0, 5.0)
SYSTEM_SCHEMAS = ("information_schema",)          # and every pg_* schema
KEY_TYPES = {"p": "primary", "u": "unique", "f": "foreign"}
CHAR_TYPES = {1042, 1043}           # bpchar, varchar: atttypmod - 4 is the length
NUMERIC_TYPE = 1700

_SIMPLE = re.compile(r"^[a-z_][a-z0-9_]*$")


class QueryStopped(Exception):
    """The statement was cancelled because the walk was told to stop."""


class PlaceTimeout(Exception):
    """A catalogue statement ran past DS_DISCOVER_STATEMENT_SEC."""


def _sqlstate(exc):
    return getattr(exc, "pgcode", None)


def _is_link_error(exc):
    try:
        import psycopg2
    except ImportError:
        return False
    return isinstance(exc, (psycopg2.OperationalError, psycopg2.InterfaceError)) and _sqlstate(exc) not in (
        "57014", "55P03")


class SchemaUnit(dd.Unit):
    __slots__ = ("oid", "owner")

    def __init__(self, oid, name, owner):
        super().__init__(name)
        self.oid = oid
        self.owner = owner


class Session(object):
    """One connection, set up for walking: autocommit, read-only, the statement and lock limits."""

    def __init__(self, handle, statement_sec):
        self.handle = handle
        self.conn = handle.client
        self.keywords = set()
        try:
            self.conn.rollback()
        except Exception:
            pass
        self.conn.autocommit = True
        cur = self.conn.cursor()
        try:
            cur.execute("set default_transaction_read_only = on")
            cur.execute("set statement_timeout = %s", (int(statement_sec * 1000),))
            cur.execute("set lock_timeout = %s", (LOCK_TIMEOUT_MS,))
            cur.execute("select word from pg_get_keywords() where catcode <> 'U'")
            self.keywords = {r[0] for r in cur.fetchall()}
        finally:
            cur.close()

    def quote(self, ident):
        """quote_ident(), as the server writes it: bare when it can be, double quotes when it must."""
        if _SIMPLE.match(ident) and ident not in self.keywords:
            return ident
        return '"' + ident.replace('"', '""') + '"'


@dd.register
class PostgresWalker(dd.Walker):
    source_type = "postgres"
    by = "schema"
    default_threads = 1             # V1 walks one table at a time; DS_DISCOVER_THREADS raises it

    def __init__(self, ctx):
        super().__init__(ctx)
        self.host = str(getattr(ctx.handle, "shown_host", None) or ctx.connection.get("host") or "").strip()
        self._lock = threading.Lock()
        self._sessions = {}             # thread id -> the Session that thread is using
        self._spare = []                # Sessions no thread is using
        self._claim_handle_used = False # the claim's own handle goes to the first thread that asks
        self._opened = []               # handles this walker signed in itself: closed by close()
        self._busy = set()              # connections with a statement running, for the stop watcher
        self._closed = threading.Event()
        self.schemas = []
        self.tables = []
        self._watcher = threading.Thread(target=self._watch, name="ds-pg-stop", daemon=True)
        self._watcher.start()

    # ---- connections
    def _watch(self):
        while not self._closed.is_set():
            if self.ctx.wait_stop(0.5):
                with self._lock:
                    busy = list(self._busy)
                for conn in busy:
                    try:
                        conn.cancel()
                    except Exception:
                        pass
                if self._closed.wait(0.5):
                    return

    def session(self):
        tid = threading.get_ident()
        s = self._sessions.get(tid)
        if s is not None:
            return s
        with self._lock:
            s = self._spare.pop() if self._spare else None
            take_claims = s is None and not self._claim_handle_used
            if take_claims:
                self._claim_handle_used = True
        if s is None:
            s = Session(self.ctx.handle if take_claims else self._open(), self.ctx.statement_sec)
        with self._lock:
            self._sessions[tid] = s
        return s

    def release_session(self):
        """This thread is done with its connection for now: another thread may take it."""
        with self._lock:
            s = self._sessions.pop(threading.get_ident(), None)
            if s is not None:
                self._spare.append(s)

    def _open(self):
        handle = self.ctx.open_handle()
        with self._lock:
            self._opened.append(handle)
        return handle

    def reconnect(self):
        """The connection broke: sign in again through the library. Its code, when that fails, is the release's."""
        with self._lock:
            old = self._sessions.pop(threading.get_ident(), None)
        if old is not None and old.handle is not self.ctx.handle:
            try:
                old.handle.close()
            except Exception:
                pass
        s = Session(self._open(), self.ctx.statement_sec)
        with self._lock:
            self._sessions[threading.get_ident()] = s
        return s

    def close(self):
        self._closed.set()
        with self._lock:
            opened, self._opened = self._opened, []
        for h in opened:
            try:
                h.close()
            except Exception:
                pass

    def query(self, sql, args=None):
        """One catalogue statement. Cancelled at once when the walk is told to stop (QueryStopped), limited to
        DS_DISCOVER_STATEMENT_SEC (PlaceTimeout)."""
        self.ctx.stop_point()
        s = self.session()
        with self._lock:
            self._busy.add(s.conn)
        try:
            cur = s.conn.cursor()
            try:
                cur.execute(sql, args)
                return cur.fetchall()
            finally:
                cur.close()
        except Exception as e:
            if _sqlstate(e) == "57014":
                if self.ctx.stopping():
                    raise dd.WalkStopped()
                raise PlaceTimeout()
            raise
        finally:
            with self._lock:
                self._busy.discard(s.conn)

    # ---- the filter
    @staticmethod
    def _list_value(scope, key):
        v = scope.get(key)
        if v is None:
            return []
        if isinstance(v, str):
            v = v.split(",")
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            raise dd.FilterInvalid(key)
        return [x.strip() for x in v if x.strip()]

    def tables_for(self, schema):
        """The table names the filter keeps in this schema: None for all of them. An entry is a table's name,
        or schema.table."""
        if not self.tables:
            return None
        out = set()
        for t in self.tables:
            if "." in t:
                sch, _dot, name = t.partition(".")
                if sch == schema:
                    out.add(name)
            out.add(t)                  # also as a bare name: a table's name may hold a dot
        return sorted(out)

    # ---- units
    def units(self):
        try:
            return self._units()
        finally:
            self.release_session()

    def _units(self):
        scope = self.ctx.scope
        self.schemas = self._list_value(scope, "schemas")
        self.tables = self._list_value(scope, "tables")
        sql = ("select n.oid, n.nspname, r.rolname from pg_namespace n left join pg_roles r on r.oid = n.nspowner "
               "where n.nspname not like 'pg\\_%%' and n.nspname <> all(%s)")
        args = [list(SYSTEM_SCHEMAS)]
        if self.schemas:
            sql += " and n.nspname = any(%s)"
            args.append(self.schemas)
        rows = self._with_link(lambda: self.query(sql + " order by n.nspname", args))
        units = [SchemaUnit(oid, name, owner) for oid, name, owner in rows]
        if self.tables:
            # a schema with none of the filter's tables is not a unit
            candidates = sorted({t for t in self.tables} | {t.partition(".")[2] for t in self.tables if "." in t})
            found = {}
            for nsp, rel in self._with_link(lambda: self.query(
                    "select relnamespace, relname from pg_class where relkind in ('r', 'p') and not relispartition "
                    "and relname = any(%s)", (candidates,))):
                found.setdefault(nsp, set()).add(rel)
            units = [u for u in units if found.get(u.oid, set()) & set(self.tables_for(u.id))]
        return units

    def _with_link(self, fn):
        """fn, again once after signing in afresh when the connection broke."""
        try:
            return fn()
        except Exception as e:
            if not _is_link_error(e):
                raise
        self.reconnect()
        return fn()

    # ---- one schema
    def walk_unit(self, unit):
        names = self.tables_for(unit.id)
        after = ""
        tries = 0
        while True:
            try:
                page = self.table_page(unit, names, after)
            except dd.WalkStopped:
                raise
            except (PlaceTimeout, Exception) as e:
                if not isinstance(e, PlaceTimeout) and not _is_link_error(e):
                    raise
                if _is_link_error(e):
                    self.reconnect()            # raises the library's code when the source is out of reach
                tries += 1
                if tries >= PLACE_TRIES:
                    self.unlisted_schema(unit, "timed out" if isinstance(e, PlaceTimeout) else "connection lost")
                    return
                dd.log.info(dd.kv(discover="place_retry", run=self.ctx.run_id, round=tries))
                self.ctx.sleep(PLACE_RETRY_DELAYS[min(tries - 1, len(PLACE_RETRY_DELAYS) - 1)])
                continue
            tries = 0
            if not page:
                return
            for el in page:
                self.ctx.emit(el)
            after = page[-1]["name"]
            if len(page) < PAGE:
                return

    def unlisted_schema(self, unit, why):
        self.ctx.emit(self.ctx.unlisted(key=unit.id, name=unit.id, path="", under=unit.id, obj_type="postgres",
                                        obj_subtype="schema", params={"reason": why}, host=self.host))

    def table_page(self, unit, names, after):
        """Up to PAGE tables of the schema whose name sorts after `after`, as elements."""
        sql = ("select c.oid, c.relname, c.relkind, c.reltuples, r.rolname from pg_class c "
               "left join pg_roles r on r.oid = c.relowner "
               "where c.relnamespace = %s and c.relkind in ('r', 'p') and not c.relispartition "
               "and c.relname::text collate \"C\" > %s collate \"C\"")
        args = [unit.oid, after]
        if names is not None:
            sql += " and c.relname = any(%s)"
            args.append(names)
        sql += " order by c.relname::text collate \"C\" limit %s"
        args.append(PAGE)
        rows = self.query(sql, args)
        if not rows:
            return []
        oids = [r[0] for r in rows]
        sizes = self.sizes(oids, [r[0] for r in rows if r[2] == "p"])
        counts = self.partition_rows([r[0] for r in rows if r[2] == "p"])
        columns = self.columns(oids)
        constraints = self.constraints(oids)
        s = self.session()
        out = []
        for oid, name, kind, reltuples, owner in rows:
            cols = columns.get(oid, [])
            cons = constraints.get(oid, [])
            keyed = {}
            for con in cons:
                for c in con["columns"]:
                    keyed.setdefault(c, con["type"])        # primary first: constraints come primary, unique, foreign
            for c in cols:
                if c["name"] in keyed:
                    c["key"] = keyed[c["name"]]
            scan_cols = [s.quote(c["name"]) for c in cols if not c["type"].startswith("bytea")]
            scan_cols = scan_cols[:SCAN_SQL_MAX_COLS]
            scan_sql = ("select " + ", ".join(scan_cols) + " from " + s.quote(unit.id) + "." + s.quote(name)) \
                if scan_cols else ""
            if kind == "p":
                rows_n = counts.get(oid)
            else:
                rows_n = int(reltuples) if reltuples is not None and reltuples >= 0 else None
            owners = [{"type": "role", "id": owner, "name": owner, "email": None, "source": "table.owner"}] \
                if owner else []
            if unit.owner and unit.owner != owner:
                owners.append({"type": "role", "id": unit.owner, "name": unit.owner, "email": None,
                               "source": "schema.owner"})
            out.append({"key": unit.id + "." + name, "parent_key": None, "host": self.host, "path": unit.id,
                        "name": name, "obj_type": "postgres", "obj_subtype": "table", "bytes": sizes.get(oid),
                        "rows": rows_n, "created_at": None, "modified_at": None, "accessed_at": None,
                        "owners": owners, "to_scan": bool(scan_sql), "source": {"scan_sql": scan_sql},
                        "schema": {"columns": cols, "constraints": cons}, "metadata": {}})
        return out

    def sizes(self, oids, partitioned):
        """pg_total_relation_size for each table; for a partitioned table, the sum over its partitions.
        A table whose lock can't be had in LOCK_TIMEOUT_MS is sized alone, and gets null if it still can't."""
        tree = ("with recursive t(top, oid) as (select x, x from unnest(%s::oid[]) x "
                "union all select t.top, i.inhrelid from t join pg_inherits i on i.inhparent = t.oid) ")
        try:
            got = dict(self.query("select x, pg_total_relation_size(x) from unnest(%s::oid[]) x", (oids,)))
            if partitioned:
                got.update(dict(self.query(tree + "select top, sum(pg_total_relation_size(oid))::bigint from t "
                                           "group by top", (partitioned,))))
        except Exception as e:
            if _sqlstate(e) != "55P03":
                raise
            got = {}
            for oid in oids:
                try:
                    if oid in partitioned:
                        r = self.query(tree + "select sum(pg_total_relation_size(oid))::bigint from t", ([oid],))
                    else:
                        r = self.query("select pg_total_relation_size(%s::oid)", (oid,))
                    got[oid] = r[0][0]
                except Exception as e2:
                    if _sqlstate(e2) != "55P03":
                        raise
                    got[oid] = None
        return {k: (int(v) if v is not None else None) for k, v in got.items()}

    def partition_rows(self, partitioned):
        if not partitioned:
            return {}
        rows = self.query(
            "with recursive t(top, oid) as (select x, x from unnest(%s::oid[]) x "
            "union all select t.top, i.inhrelid from t join pg_inherits i on i.inhparent = t.oid) "
            "select t.top, sum(c.reltuples) filter (where c.relkind = 'r' and c.reltuples >= 0), "
            "bool_or(c.relkind = 'r' and c.reltuples < 0) from t join pg_class c on c.oid = t.oid group by t.top",
            (partitioned,))
        return {top: (None if never or total is None else int(total)) for top, total, never in rows}

    def columns(self, oids):
        rows = self.query(
            "select a.attrelid, a.attname, format_type(a.atttypid, a.atttypmod), a.atttypid, a.atttypmod, "
            "a.attnotnull, pg_get_expr(d.adbin, d.adrelid) from pg_attribute a "
            "left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum "
            "where a.attrelid = any(%s::oid[]) and a.attnum > 0 and not a.attisdropped "
            "order by a.attrelid, a.attnum", (oids,))
        out = {}
        for relid, name, typ, typid, typmod, notnull, default in rows:
            precision = scale = length = None
            if typid in CHAR_TYPES and typmod > 4:
                length = typmod - 4
            elif typid == NUMERIC_TYPE and typmod > 4:
                precision, scale = ((typmod - 4) >> 16) & 0xFFFF, (typmod - 4) & 0xFFFF
            out.setdefault(relid, []).append({"name": name, "type": typ, "nullable": not notnull, "default": default,
                                              "precision": precision, "scale": scale, "max_length": length})
        return out

    def constraints(self, oids):
        rows = self.query(
            "select c.conrelid, c.conname, c.contype, "
            "array(select a.attname from unnest(c.conkey) with ordinality k(n, i) "
            "      join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.n order by k.i), "
            "fn.nspname, fc.relname, "
            "array(select a.attname from unnest(c.confkey) with ordinality k(n, i) "
            "      join pg_attribute a on a.attrelid = c.confrelid and a.attnum = k.n order by k.i) "
            "from pg_constraint c left join pg_class fc on fc.oid = c.confrelid "
            "left join pg_namespace fn on fn.oid = fc.relnamespace "
            "where c.conrelid = any(%s::oid[]) and c.contype in ('p', 'u', 'f') "
            "order by c.conrelid, position(c.contype::text in 'puf'), c.conname", (oids,))
        out = {}
        for relid, name, kind, cols, fschema, ftable, fcols in rows:
            con = {"name": name, "type": KEY_TYPES[kind], "columns": list(cols or [])}
            if kind == "f":
                con["references"] = {"schema": fschema, "table": ftable, "columns": list(fcols or [])}
            out.setdefault(relid, []).append(con)
        return out
