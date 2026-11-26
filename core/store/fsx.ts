import {
  chmodSync,
  closeSync,
  existsSync,
  lstatSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export function ensureDir(dir: string): void {
  mkdirSync(dir, { recursive: true, mode: DIR_MODE });
}

/**
 * The state root may sit in a shared temp directory. Refuse to use it if another
 * user could have planted it: it must be a real directory (not a symlink), owned
 * by us, and is forced to mode 0700 so nobody else can read or swap its files.
 */
export function ensurePrivateDir(dir: string): void {
  ensureDir(dir);
  const st = lstatSync(dir);
  if (st.isSymbolicLink() || !st.isDirectory()) throw new Error("state directory is not a private directory");
  if (typeof process.getuid === "function" && st.uid !== process.getuid()) {
    throw new Error("state directory is owned by another user");
  }
  if (process.platform !== "win32" && (st.mode & 0o077) !== 0) chmodSync(dir, DIR_MODE);
}

/** Best-effort directory fsync so a rename survives power loss (no-op where unsupported). */
function fsyncDir(dir: string): void {
  let fd: number | undefined;
  try {
    fd = openSync(dir, "r");
    fsyncSync(fd);
  } catch {
    // Windows and some filesystems do not allow fsync on directories.
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * On Windows, replacing a file that another process has open fails with
 * EPERM/EACCES/EBUSY for a moment; retry briefly. POSIX rename never does this.
 */
function renameWithRetry(from: string, to: string): void {
  for (let attempt = 0; ; attempt++) {
    try {
      renameSync(from, to);
      return;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (attempt >= 250 || (code !== "EPERM" && code !== "EACCES" && code !== "EBUSY")) throw err;
      sleepMs(4);
    }
  }
}

/**
 * Replace `path` atomically: write a private temp file in the same directory,
 * fsync it, then rename over the target. Readers see the old or the new file,
 * never a partial one.
 */
export function atomicWriteFile(path: string, data: string | Buffer): void {
  const dir = dirname(path);
  ensureDir(dir);
  const tmp = join(dir, `.tmp-${process.pid}-${randomBytes(6).toString("hex")}`);
  const fd = openSync(tmp, "wx", FILE_MODE);
  try {
    writeSync(fd, typeof data === "string" ? Buffer.from(data, "utf8") : data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameWithRetry(tmp, path);
  } catch (err) {
    try {
      unlinkSync(tmp);
    } catch {
      // ignore cleanup failure; the original error matters
    }
    throw err;
  }
  fsyncDir(dir);
}

/** Append one line and fsync before returning (used for the audit log). */
export function appendDurable(path: string, line: string): void {
  ensureDir(dirname(path));
  const fd = openSync(path, "a", FILE_MODE);
  try {
    writeSync(fd, Buffer.from(line.endsWith("\n") ? line : `${line}\n`, "utf8"));
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

export function readTextIfExists(path: string): string | undefined {
  // On Windows a read can briefly fail while another process atomically replaces the file.
  for (let attempt = 0; ; attempt++) {
    if (!existsSync(path)) return undefined;
    try {
      return readFileSync(path, "utf8");
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === "ENOENT") return undefined;
      if (attempt >= 250 || (code !== "EPERM" && code !== "EACCES" && code !== "EBUSY")) throw err;
      sleepMs(4);
    }
  }
}

const sleepCell = new Int32Array(new SharedArrayBuffer(4));
function sleepMs(ms: number): void {
  Atomics.wait(sleepCell, 0, 0, ms);
}

// A request holds the lock for a few milliseconds. Keep the total wait well
// under the judge's 8 s per-operation timeout.
const LOCK_WAIT_MS = 6_000;
// A lock without a readable PID (still being written, or garbage) is stale after this long.
const LOCK_STALE_MS = 3_000;
// A lock whose holder still looks alive is only treated as abandoned after this long (PID reuse).
const LOCK_ABANDONED_MS = 20_000;
// A stale-lock breaker that stays longer than this was killed mid-break.
const BREAKER_STALE_MS = 1_000;

/** True if the lock's holder has exited (or the lock is unreadable/abandoned for long enough). */
function lockIsStale(lockPath: string): boolean {
  let age: number;
  let pid: number;
  try {
    age = Date.now() - statSync(lockPath).mtimeMs;
    pid = Number.parseInt(readFileSync(lockPath, "utf8").split(" ")[0] ?? "", 10);
  } catch {
    return false; // vanished or unreadable right now: just retry
  }
  if (!Number.isInteger(pid) || pid <= 0) return age > LOCK_STALE_MS;
  if (pid !== process.pid) {
    try {
      process.kill(pid, 0); // signal 0 = existence check only
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ESRCH") return true;
    }
  }
  return age > LOCK_ABANDONED_MS;
}

/**
 * Break a stale lock without racing other waiters (red-team F1). Breaking is
 * exclusive: only the process that creates `.lock.break` may unlink the lock,
 * and it re-checks staleness while holding it, so it can never delete a fresh
 * lock that another waiter has just taken.
 */
function breakStaleLock(lockPath: string): void {
  if (!lockIsStale(lockPath)) return;
  const breaker = `${lockPath}.break`;
  let b: number;
  try {
    b = openSync(breaker, "wx", FILE_MODE);
  } catch {
    try {
      if (Date.now() - statSync(breaker).mtimeMs > BREAKER_STALE_MS) unlinkSync(breaker);
    } catch {
      // breaker vanished or is busy; retry later
    }
    return;
  }
  try {
    if (lockIsStale(lockPath)) unlinkSync(lockPath);
  } catch {
    // lock already gone
  } finally {
    closeSync(b);
    try {
      unlinkSync(breaker);
    } catch {
      // already removed
    }
  }
}

/**
 * Cross-process mutual exclusion. The judge starts one process per request, so
 * concurrent requests must not interleave read-modify-write cycles on state.
 * The lock file records the holder's PID and a random token: a lock whose holder
 * has exited (for example a request killed mid-way) is broken, exclusively, by
 * one waiter; a holder only ever removes a lock that still carries its own token.
 */
export function withLock<T>(dir: string, fn: () => T): T {
  ensurePrivateDir(dir);
  const lockPath = join(dir, ".lock");
  const token = `${process.pid} ${Date.now()} ${randomBytes(8).toString("hex")}`;
  const deadline = Date.now() + LOCK_WAIT_MS;
  let fd: number | undefined;
  while (fd === undefined) {
    try {
      fd = openSync(lockPath, "wx", FILE_MODE);
      writeSync(fd, Buffer.from(token, "utf8"));
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      // Windows cannot reopen a file whose deletion is still pending (red-team F5): that is "busy", not an error.
      const pendingDelete = process.platform === "win32" && (code === "EPERM" || code === "EACCES");
      if (code !== "EEXIST" && !pendingDelete) throw err;
      if (code === "EEXIST") breakStaleLock(lockPath);
      if (Date.now() > deadline) throw new Error("state lock timeout");
      sleepMs(pendingDelete ? 2 : 5);
    }
  }
  try {
    return fn();
  } finally {
    closeSync(fd);
    try {
      if (readFileSync(lockPath, "utf8") === token) unlinkSync(lockPath);
    } catch {
      // already removed
    }
  }
}
