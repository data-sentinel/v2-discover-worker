# walk_directory.py - the 'directory' walk: the files on a share mounted for the workers
#
# Port of V1's file_system_generator, file_filter and OwnerResolver (ds_discover_worker.py), to 01 and
# the rulings of 2026-46-80:
#   key      the path below root_path with the name, no leading slash      hr/onboarding/2026/offer.docx
#   path     '/' and the folder below root_path                            /hr/onboarding/2026   (root: /)
#   source   empty: scan rebuilds the full path from root_path and key. Only a name that isn't UTF-8
#            carries 'path_b64', the raw bytes of the path below root_path, because its key is escaped
#   units    each include path's own files, and each top folder under it, by path
#   owners   the file's owner and group and its folder's owner, as V1 resolves them, LDAP left out
#
# Nothing is opened: folders are listed and entries stat'ed, so no file's access time moves. Links,
# devices, sockets and pipes are not handed in. A folder the account may not enter is handed in as unlisted
# at once; one that timed out or lost its connection is tried twice more first. Calls that touch the share run on a helper thread with a time limit, so a
# share that stops answering can't hold the walk past a stop or past DS_DISCOVER_STATEMENT_SEC.
import base64
import ctypes
import errno
import grp
import os
import pwd
import re
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timezone

import ds_connect_lib as dcl
import ds_discover as dd

PAGE = 500                          # entries read between two stop points
PLACE_TRIES = 3                     # a folder that can't be listed: tried this many times in all
PLACE_RETRY_DELAYS = (2.0, 5.0)     # seconds before the second and the third try
SMB_FSTYPES = {"cifs", "smb3", "smbfs"}
SHARE_NOTE = "mounted share: os owner is the mount mapping, not the NTFS owner"
# what another try can pass: a dropped connection, a busy share. A timeout too (ShareTimeout). Not a
# permission denied, which is an unlisted place at once (architect 2026-47-01, 3.4)
RETRY_ERRNOS = {errno.EIO, errno.ENOTCONN, errno.ESTALE, errno.ETIMEDOUT, errno.EHOSTDOWN, errno.EHOSTUNREACH,
                errno.ENODEV, errno.ECONNRESET, errno.ECONNABORTED, errno.ENETUNREACH, errno.ENETDOWN,
                errno.EBUSY, errno.EAGAIN, errno.EINTR}


def retryable(exc):
    return isinstance(exc, ShareTimeout) or getattr(exc, "errno", None) in RETRY_ERRNOS


# ------------------------------------------------------------------------------------------------
# owners: V1's OwnerResolver without LDAP
# ------------------------------------------------------------------------------------------------
def read_colon_file(path):
    """passwd / group rows by their numeric id (the third field). {} when absent or unreadable."""
    rows = {}
    if not path:
        return rows
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.rstrip("\n").split(":")
                if len(fields) >= 3 and fields[2].isdigit():
                    rows.setdefault(int(fields[2]), fields)
    except OSError:
        pass
    return rows


def sid_from_security_descriptor(sd):
    """The owner SID string from a self-relative NT security descriptor (system.cifs_acl), or None."""
    try:
        owner_off = struct.unpack_from("<I", sd, 4)[0]
        if owner_off == 0:
            return None
        rev, n_sub = sd[owner_off], sd[owner_off + 1]
        authority = int.from_bytes(sd[owner_off + 2:owner_off + 8], "big")
        subs = struct.unpack_from("<%dI" % n_sub, sd, owner_off + 8)
    except (struct.error, IndexError, TypeError):
        return None
    return "S-%d-%d" % (rev, authority) + "".join("-%d" % s for s in subs)


def ntfs_owner_sid(path):
    """The NTFS owner of a file or folder on a CIFS mount, read from its security descriptor (an
    extended attribute: the file's content is not opened). None when the mount doesn't give it."""
    try:
        sd = os.getxattr(path, "system.cifs_acl", follow_symlinks=False)
    except (OSError, AttributeError):
        return None
    return sid_from_security_descriptor(sd)


def mount_table():
    """(mount point, file system type), longest point first."""
    mounts = []
    try:
        with open("/proc/self/mounts", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                fields = line.split()
                if len(fields) >= 3:
                    point = _unescape_mount(fields[1])
                    mounts.append((point, fields[2]))
    except OSError:
        pass
    return sorted(mounts, key=lambda m: len(m[0]), reverse=True)


def _unescape_mount(s):
    # /proc/mounts writes a space as \040, a tab as \011 ...
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)


class OwnerResolver(object):
    """Names for the numeric owners a mounted share reports: the owner map file, then the container's own
    users and groups, then the host's passwd and group files. A SID is named from the map file only.
    What can't be named is handed in by its raw id (ruling 7)."""

    def __init__(self, owner_map, host_passwd, host_group):
        self._map = {}
        for section in ("users", "groups", "sids"):
            v = (owner_map or {}).get(section)
            self._map[section] = v if isinstance(v, dict) else {}
        self._passwd = read_colon_file(host_passwd)
        self._group = read_colon_file(host_group)
        self._names = {}
        self._entries = {}
        self._lock = threading.Lock()

    def _from_map(self, section, key):
        hit = self._map[section].get(str(key))
        if isinstance(hit, str):
            return {"name": hit}
        return hit if isinstance(hit, dict) else None

    def _resolve(self, cache_key, sources):
        if cache_key in self._names:
            return self._names[cache_key]
        name = email = None
        for source in sources:
            try:
                hit = source()
            except Exception:
                hit = None
            if hit:
                name = name or (hit.get("name") or None)
                email = email or (hit.get("email") or None)
                if name and email:
                    break
        with self._lock:
            self._names[cache_key] = (name, email)
        return name, email

    def user(self, uid):
        return self._resolve(("uid", uid), (
            lambda: self._from_map("users", uid),
            lambda: {"name": pwd.getpwuid(uid).pw_name},
            lambda: {"name": self._passwd[uid][0]} if uid in self._passwd else None))

    def group(self, gid):
        return self._resolve(("gid", gid), (
            lambda: self._from_map("groups", gid),
            lambda: {"name": grp.getgrgid(gid).gr_name},
            lambda: {"name": self._group[gid][0]} if gid in self._group else None))

    def sid(self, sid):
        return self._resolve(("sid", sid), (lambda: self._from_map("sids", sid),))

    def owner(self, uid, sid, on_share, source):
        """V1's owner_entry: on an SMB mount, the real NTFS owner when the mount gives it."""
        cache_key = ("owner", uid, sid, on_share, source)
        hit = self._entries.get(cache_key)
        if hit is not None:
            return hit
        if sid:
            name, email = self.sid(sid)
            entry = {"type": "os_user", "id": sid, "name": name, "email": email, "source": source}
        else:
            name, email = self.user(uid)
            entry = {"type": "os_user", "id": str(uid), "name": name, "email": email, "source": source}
            if on_share:
                entry["note"] = SHARE_NOTE
        with self._lock:
            self._entries[cache_key] = entry
        return entry

    def group_entry(self, gid, on_share, source):
        cache_key = ("group", gid, on_share, source)
        hit = self._entries.get(cache_key)
        if hit is not None:
            return hit
        name, email = self.group(gid)
        entry = {"type": "os_group", "id": str(gid), "name": name, "email": email, "source": source}
        if on_share:
            entry["note"] = SHARE_NOTE
        with self._lock:
            self._entries[cache_key] = entry
        return entry


def merge_owners(*entries):
    """V1's add_owner: one entry per owner, the first source seen kept. Deduplicated on type and id, so a
    user and a group with the same number are both kept."""
    seen, out = set(), []
    for e in entries:
        if e is None:
            continue
        k = (e["type"], e["id"])
        if k in seen:
            continue
        seen.add(k)
        out.append(e)
    return out


# ------------------------------------------------------------------------------------------------
# names that aren't UTF-8
# ------------------------------------------------------------------------------------------------
def shown(s):
    """A name as it can be handed in. Bytes that aren't UTF-8 (Python keeps them as surrogates) become
    \\xNN, because a JSON document can't carry them."""
    try:
        s.encode("utf-8")
        return s
    except UnicodeEncodeError:
        return s.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def is_odd(s):
    try:
        s.encode("utf-8")
        return False
    except UnicodeEncodeError:
        return True


def utc(ts):
    """V1's safe_datetime, as a timestamp with a zone."""
    try:
        if ts and ts > 0:
            return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")
    except (ValueError, OSError, OverflowError):
        pass
    return None


# ------------------------------------------------------------------------------------------------
# a file's stat, with its birth time: statx(2) through the C library, no compiled extension
# ------------------------------------------------------------------------------------------------
class _StatxTimestamp(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_uint32), ("_reserved", ctypes.c_int32)]


class _Statx(ctypes.Structure):
    # struct statx as the kernel defines it (include/uapi/linux/stat.h): 256 bytes
    _fields_ = [("stx_mask", ctypes.c_uint32), ("stx_blksize", ctypes.c_uint32), ("stx_attributes", ctypes.c_uint64),
                ("stx_nlink", ctypes.c_uint32), ("stx_uid", ctypes.c_uint32), ("stx_gid", ctypes.c_uint32),
                ("stx_mode", ctypes.c_uint16), ("_spare0", ctypes.c_uint16), ("stx_ino", ctypes.c_uint64),
                ("stx_size", ctypes.c_uint64), ("stx_blocks", ctypes.c_uint64), ("stx_attributes_mask", ctypes.c_uint64),
                ("stx_atime", _StatxTimestamp), ("stx_btime", _StatxTimestamp), ("stx_ctime", _StatxTimestamp),
                ("stx_mtime", _StatxTimestamp), ("stx_rdev_major", ctypes.c_uint32), ("stx_rdev_minor", ctypes.c_uint32),
                ("stx_dev_major", ctypes.c_uint32), ("stx_dev_minor", ctypes.c_uint32), ("_spare", ctypes.c_uint64 * 14)]


AT_FDCWD = -100
AT_SYMLINK_NOFOLLOW = 0x100
AT_NO_AUTOMOUNT = 0x800
STATX_BASIC_STATS = 0x7FF
STATX_BTIME = 0x800


def _load_statx():
    try:
        fn = ctypes.CDLL(None, use_errno=True).statx
    except (OSError, AttributeError):
        return None                     # a C library without statx (glibc before 2.28): lstat, no birth time
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.POINTER(_Statx)]
    fn.restype = ctypes.c_int
    return fn


_statx = _load_statx()


class FileStat(object):
    """What the walk keeps of a file's stat. birth is None where the file system reports no birth time."""
    __slots__ = ("size", "uid", "gid", "atime", "mtime", "birth")

    def __init__(self, size, uid, gid, atime, mtime, birth):
        self.size, self.uid, self.gid, self.atime, self.mtime, self.birth = size, uid, gid, atime, mtime, birth


def _ts(t):
    return t.tv_sec + t.tv_nsec / 1e9


def file_stat(path):
    """statx with the birth time asked for, not following a link; os.lstat (and no birth time) where the C
    library or the kernel has no statx. Raises OSError as lstat would."""
    global _statx
    if _statx is not None:
        buf = _Statx()
        if _statx(AT_FDCWD, os.fsencode(path), AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT,
                  STATX_BASIC_STATS | STATX_BTIME, ctypes.byref(buf)) == 0:
            birth = _ts(buf.stx_btime) if buf.stx_mask & STATX_BTIME else None
            return FileStat(buf.stx_size, buf.stx_uid, buf.stx_gid, _ts(buf.stx_atime), _ts(buf.stx_mtime), birth)
        err = ctypes.get_errno()
        if err != errno.ENOSYS:
            raise OSError(err, os.strerror(err))
        _statx = None                   # a kernel (or a seccomp profile) without statx: lstat from here on
    st = os.lstat(path)
    return FileStat(st.st_size, st.st_uid, st.st_gid, st.st_atime, st.st_mtime, None)


# ------------------------------------------------------------------------------------------------
# calls that touch the share, on a helper thread with a limit
# ------------------------------------------------------------------------------------------------
class ShareTimeout(Exception):
    """A call on the share didn't come back within the limit."""


class ShareCalls(object):
    """One helper thread per walk thread. A call that hangs (a share that stopped answering) is left
    behind on its thread, a new thread takes over, and the walk goes on or stops: it never waits on it."""

    def __init__(self, ctx, limit):
        self.ctx = ctx
        self.limit = limit
        self.pool = None
        self.abandoned = 0          # helpers left behind on a call that didn't come back

    def run(self, fn, *args):
        if self.pool is None:
            self.pool = ThreadPoolExecutor(1, thread_name_prefix="ds-share")
        fut = self.pool.submit(fn, *args)
        t_end = time.monotonic() + self.limit
        while True:
            try:
                return fut.result(timeout=0.5)
            except FutureTimeout:
                stopping = self.ctx.stopping()
                if not stopping and time.monotonic() < t_end:
                    continue
                self.pool.shutdown(wait=False, cancel_futures=True)
                self.pool = None
                self.abandoned += 1
                if stopping:
                    raise dd.WalkStopped()
                raise ShareTimeout()


def _open_folder(real, want_sid):
    it = os.scandir(real)
    try:
        st = os.lstat(real)
    except OSError:
        st = None
    sid = ntfs_owner_sid(real) if want_sid else None
    return it, st, sid


def _read_page(it, want_sid):
    """Up to PAGE entries: (name, kind, FileStat or None, error or None, owner SID or None)."""
    out = []
    for entry in it:
        st = err = sid = None
        try:
            if entry.is_symlink():
                kind = "link"
            elif entry.is_dir(follow_symlinks=False):
                kind = "dir"
            elif entry.is_file(follow_symlinks=False):
                kind = "file"
            else:
                kind = "other"
        except FileNotFoundError:
            kind = "gone"
        except OSError as e:
            kind, err = "file", e
        if kind == "file" and err is None:
            try:
                st = file_stat(entry.path)
            except FileNotFoundError:
                kind = "gone"
            except OSError as e:
                err = e
            if want_sid and st is not None:
                sid = ntfs_owner_sid(entry.path)
        out.append((entry.name, kind, st, err, sid))
        if len(out) >= PAGE:
            break
    return out


def _close(it):
    try:
        it.close()
    except Exception:
        pass


def why_text(exc):
    """A folder's failure as the reason's few words. Never the path."""
    if isinstance(exc, ShareTimeout):
        return "timed out"
    if isinstance(exc, PermissionError):
        return "permission denied"
    if isinstance(exc, OSError) and exc.errno:
        return os.strerror(exc.errno).lower()
    return type(exc).__name__


class FolderUnit(dd.Unit):
    """A top folder of an include path (walked to the bottom), or an include path's own files."""
    __slots__ = ("rel", "deep")

    def __init__(self, rel, deep):
        super().__init__("/" + shown(rel) if rel else "/")
        self.rel = rel
        self.deep = deep


@dd.register
class DirectoryWalker(dd.Walker):
    source_type = "directory"
    by = "path"
    default_threads = 1             # V1 walks one folder at a time; DS_DISCOVER_THREADS raises it

    def __init__(self, ctx):
        super().__init__(ctx)
        s = ctx.settings
        self.owners = OwnerResolver(getattr(s, "owner_map", {}), getattr(s, "host_passwd", None),
                                    getattr(s, "host_group", None))
        self.mounts = mount_table()
        self.real_root = ctx.handle.client        # the library resolved it; built on the event loop, so no I/O on the share
        self.stored_root = str(getattr(ctx.handle, "root_path", None) or ctx.connection.get("root_path") or "")
        self.root_dev = None
        self.include = []
        self.exclude = []
        self.types = ()
        self._local = threading.local()
        self._on_share = {}

    # ---- helpers
    @property
    def share(self):
        calls = getattr(self._local, "calls", None)
        if calls is None:
            calls = self._local.calls = ShareCalls(self.ctx, self.ctx.statement_sec)
        return calls

    def _connection(self, root_path=None):
        c = dict(self.ctx.connection)
        if root_path is not None:
            c["root_path"] = root_path
        return c

    def _check(self, root_path=None):
        """The library's check of the source, or of one path in its filter: raise its code when it fails."""
        res = dcl.check("directory", self._connection(root_path), timeout=dcl.DEFAULT_TIMEOUT_SEC,
                        file_roots=self.ctx.file_roots)
        if res.status != "reachable":
            raise dcl.ConnectError(res.code, res.params)

    def _file_root(self):
        best = None
        for r in self.ctx.file_roots:
            real = os.path.realpath(r)
            if self.real_root == real or self.real_root.startswith(real.rstrip(os.sep) + os.sep):
                if best is None or len(real) > len(best[1]):
                    best = (r, real)
        return best[0] if best else self.stored_root

    def check_source(self):
        """Mid-walk: is the whole source still there? The library's check, and the same mount under the
        root as at the start (a share that came unmounted leaves an empty folder that lists fine)."""
        self._check()
        try:
            dev = self.share.run(os.stat, self.real_root).st_dev
        except ShareTimeout:
            raise dcl.ConnectError("check_timeout", {"s": self.ctx.statement_sec})
        except OSError:
            raise dcl.ConnectError("path_not_found", {"root_path": self.stored_root})
        if self.root_dev is not None and dev != self.root_dev:
            raise dcl.ConnectError("root_not_mounted", {"root": self._file_root()})

    def on_share(self, real_dir):
        hit = self._on_share.get(real_dir)
        if hit is None:
            hit = False
            for point, fstype in self.mounts:
                if real_dir == point or real_dir.startswith(point.rstrip("/") + "/"):
                    hit = fstype in SMB_FSTYPES
                    break
            if len(self._on_share) < 100000:
                self._on_share[real_dir] = hit
        return hit

    def real(self, rel):
        return os.path.join(self.real_root, rel) if rel else self.real_root

    def excluded(self, rel):
        for e in self.exclude:
            if e == "" or rel == e or rel.startswith(e + "/"):
                return True
        return False

    def type_ok(self, name):
        if not self.types:
            return True
        n = name.lower()
        return any(n.endswith("." + t) for t in self.types)

    # ---- the filter
    @staticmethod
    def _list_value(scope, key):
        """A list field of the filter. A single string is taken as a list of one (a path may hold a comma);
        file types alone may also come as "docx, pdf"."""
        v = scope.get(key)
        if v is None:
            return []
        if isinstance(v, str):
            v = v.split(",") if key == "file_types" else [v]
        if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
            raise dd.FilterInvalid(key)
        return [x.strip() for x in v if x.strip()]

    def _below(self, cand, base):
        base = base.rstrip(os.sep) or os.sep
        if cand == base:
            return ""
        if cand.startswith(base.rstrip(os.sep) + os.sep):
            return cand[len(base.rstrip(os.sep)) + 1:]
        return None

    def _absolute(self, p):
        return os.path.normpath(p if os.path.isabs(p) else os.path.join(self.stored_root, p))

    def include_rel(self, p):
        """An include path, checked as the conductor checks a root_path (same roots, same real-path rule,
        same codes), then placed below root_path."""
        ab = self._absolute(p)
        self._check(ab)
        real = os.path.realpath(ab)
        rel = self._below(real, self.real_root)
        if rel is None:
            raise dd.OutOfReach("path_outside_root_path", {"path": p, "root_path": self.stored_root})
        return rel

    def exclude_rel(self, p):
        ab = self._absolute(p)
        for base in (os.path.normpath(self.stored_root), self.real_root):
            rel = self._below(ab, base)
            if rel is not None:
                return rel
        try:
            real = self.share.run(os.path.realpath, ab)
        except ShareTimeout:
            return None
        return self._below(real, self.real_root)       # outside the source: it excludes nothing

    # ---- units
    def units(self):
        self._check()
        try:
            self.root_dev = self.share.run(os.stat, self.real_root).st_dev
        except ShareTimeout:
            raise dcl.ConnectError("check_timeout", {"s": self.ctx.statement_sec})
        scope = self.ctx.scope
        self.types = tuple(sorted({t.lower().lstrip("*").lstrip(".") for t in self._list_value(scope, "file_types")}
                                  - {""}))
        self.exclude = sorted({r for r in (self.exclude_rel(p) for p in self._list_value(scope, "exclude_paths"))
                               if r is not None})
        includes = sorted({self.include_rel(p) for p in self._list_value(scope, "include_paths")}) or [""]
        # an include path inside another is walked with it
        kept = []
        for rel in includes:
            if not any(k == "" or rel == k or rel.startswith(k + "/") for k in kept):
                kept.append(rel)
        self.include = kept
        units = []
        for rel in kept:
            self.ctx.stop_point()
            if self.excluded(rel):
                continue
            units.append(FolderUnit(rel, deep=False))
            for name in self._subfolders_of_include(rel):
                child = rel + "/" + name if rel else name
                if not self.excluded(child):
                    units.append(FolderUnit(child, deep=True))
        return units

    def _subfolders_of_include(self, rel):
        real = self.real(rel)
        share = self.share
        try:
            it, _st, _sid = share.run(_open_folder, real, False)
        except (OSError, ShareTimeout) as e:
            self._refuse_include(rel, e)
        held = share.abandoned
        names = []
        try:
            while True:
                page = self.share.run(_read_page, it, False)
                if not page:
                    break
                names += [name for name, kind, _st, _err, _sid in page if kind == "dir"]
                self.ctx.stop_point()
        except (OSError, ShareTimeout) as e:
            self._refuse_include(rel, e)
        finally:
            if share.abandoned == held:
                _close(it)
        return sorted(names)

    def _refuse_include(self, rel, exc):
        """An include path that passed its check and can't be listed a moment later: check again, and say
        what the check says; when it passes, the library's code for what the listing met."""
        ab = self.real(rel)
        self.check_source()
        self._check(ab)
        if isinstance(exc, PermissionError):
            raise dcl.ConnectError("path_not_readable", {"root_path": ab})
        if isinstance(exc, ShareTimeout):
            raise dcl.ConnectError("check_timeout", {"s": self.ctx.statement_sec})
        raise dcl.ConnectError("path_not_found", {"root_path": ab})

    # ---- one unit
    def walk_unit(self, unit):
        tries = {}
        todo = [unit.rel]
        failed = []
        rounds = 0
        while todo or failed:
            if not todo:
                # a retry round: the source first (a share that went away is a release, not unlisted places),
                # then the folders that failed, after a pause
                self.check_source()
                delay = PLACE_RETRY_DELAYS[min(rounds, len(PLACE_RETRY_DELAYS) - 1)]
                rounds += 1
                dd.log.info(dd.kv(discover="place_retry", run=self.ctx.run_id, places=len(failed), round=rounds))
                self.ctx.sleep(delay)
                todo, failed = sorted(failed, reverse=True), []
            rel = todo.pop()
            try:
                subfolders = self.list_folder(rel, deep=unit.deep)
            except dd.WalkStopped:
                raise
            except (OSError, ShareTimeout) as e:
                # the source first: a share that went away, or a root that can't be listed any more, is a
                # release with the check's code, never a run of unlisted places
                self.check_source()
                if isinstance(e, (FileNotFoundError, NotADirectoryError)):
                    continue                # the source is there and this folder isn't: it was removed
                if not retryable(e):
                    self.unlisted_folder(rel, e)        # permission denied: another try can't pass
                    continue
                n = tries.get(rel, 0) + 1
                tries[rel] = n
                if n < PLACE_TRIES:
                    failed.append(rel)
                    continue
                self.unlisted_folder(rel, e)
                continue
            for child in reversed(subfolders):
                todo.append(child)
        try:
            dev = self.share.run(os.stat, self.real_root).st_dev
        except (OSError, ShareTimeout):
            dev = None
        if dev != self.root_dev:
            self.check_source()

    def unlisted_folder(self, rel, exc):
        if rel == "":
            # the root itself: that is the whole source out of reach, never an unlisted place
            raise dcl.ConnectError("path_not_readable", {"root_path": self.stored_root})
        parent, _sep, name = rel.rpartition("/")
        el = self.ctx.unlisted(key=shown(rel), name=shown(name), path="/" + shown(parent) if parent else "/",
                               under="/" + shown(rel), obj_type="document", obj_subtype="folder",
                               params={"reason": why_text(exc)}, host="directory")
        if is_odd(rel):
            el["source"] = {"path_b64": base64.b64encode(rel.encode("utf-8", "surrogateescape")).decode("ascii")}
        self.ctx.emit(el)

    def list_folder(self, rel, deep):
        """Hand in the folder's files; return its subfolders (below root_path) when deep."""
        real = self.real(rel)
        want_sid = self.on_share(real)
        share = self.share
        it, dst, dsid = share.run(_open_folder, real, want_sid)
        held = share.abandoned
        subfolders = []
        try:
            dir_owner = self.owners.owner(dst.st_uid, dsid, want_sid, "directory.owner") if dst is not None else None
            folder_odd = is_odd(rel)
            path = "/" + shown(rel) if rel else "/"
            while True:
                page = share.run(_read_page, it, want_sid)
                if not page:
                    break
                for name, kind, st, err, sid in page:
                    child = rel + "/" + name if rel else name
                    if kind == "dir":
                        if deep and not self.excluded(child):
                            subfolders.append(child)
                    elif kind == "file":
                        if self.type_ok(name) and not self.excluded(child):
                            self.ctx.emit(self.element(child, name, path, st, sid, want_sid, dir_owner,
                                                       folder_odd or is_odd(name)))
                self.ctx.stop_point()
        finally:
            if share.abandoned == held:     # else a helper that never came back may still be inside it
                _close(it)
        subfolders.sort()
        return subfolders

    def element(self, rel, name, path, st, sid, on_share, dir_owner, odd):
        if st is not None:
            owners = merge_owners(self.owners.owner(st.uid, sid, on_share, "file.owner"),
                                  self.owners.group_entry(st.gid, on_share, "file.group"), dir_owner)
            # created_at is the birth time, or null: never the inode's change time (architect 2026-47-01, 3.2)
            size, born, mtime, atime = st.size, utc(st.birth), utc(st.mtime), utc(st.atime)
        else:
            owners = merge_owners(dir_owner)
            size = born = mtime = atime = None              # listed, and the source wouldn't say more
        el = {"key": shown(rel) if odd else rel, "parent_key": None, "host": "directory", "path": path,
              "name": shown(name) if odd else name, "obj_type": "document", "obj_subtype": "filesystem",
              "bytes": size, "rows": None, "created_at": born, "modified_at": mtime, "accessed_at": atime,
              "owners": owners, "to_scan": True, "source": {}, "schema": None, "metadata": {}}
        if odd:
            el["source"] = {"path_b64": base64.b64encode(rel.encode("utf-8", "surrogateescape")).decode("ascii")}
        return el

