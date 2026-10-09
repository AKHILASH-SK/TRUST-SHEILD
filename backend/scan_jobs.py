"""
Shared scan jobs ("single flight").

Exactly ONE analysis of a link runs at any moment, whoever asks for it: the notification scanner, a tap in the Link
Gate, the Chrome extension or the portal. A later asker JOINS the running job and sees the same live stage progress
(it never starts again from the first stage), and the first finisher answers everyone. A finished decisive result is
kept for a while so the next tap is instant.
"""
import copy
import logging
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Tuple

from core_engine import scan_progress

logger = logging.getLogger("trustshield.jobs")

# how much of the progress bar each stage is worth (sandbox is the long one)
STAGE_WEIGHTS = {"threat_lists": 8, "link_analysis": 4, "reputation": 14, "sandbox": 46, "model": 10, "verdict": 18}

TTL_DANGEROUS = 6 * 3600       # a link found dangerous stays dangerous for hours
TTL_SAFE = 30 * 60
TTL_UNVERIFIED = 120           # an uncertain answer is kept only briefly: just enough to avoid an instant re-scan
JOB_WAIT_SECONDS = 75


def cache_key(url: str) -> str:
    """'https://www.x.org/' and 'http://x.org' are the same link."""
    k = (url or "").strip().lower().split("#")[0]
    for prefix in ("https://", "http://"):
        if k.startswith(prefix):
            k = k[len(prefix):]
    if k.startswith("www."):
        k = k[4:]
    return k.rstrip("/")


class ScanJob:
    def __init__(self, key: str, url: str):
        self.id = uuid.uuid4().hex
        self.key = key
        self.url = url
        self.created = time.time()
        self.finished: Optional[float] = None
        self.state = "running"            # running | done | error
        self.error = ""
        self.result: Optional[Dict[str, Any]] = None
        self.watchers: List[Tuple[int, str]] = []        # (user id, source app) that asked for the scan to be recorded
        self._lock = threading.Lock()
        self._event = threading.Event()
        self.stages: "OrderedDict[str, Dict[str, str]]" = OrderedDict(
            (sid, {"id": sid, "label": label, "status": "pending", "detail": ""}) for sid, label in scan_progress.STAGES)

    # ---- progress ---------------------------------------------------------------------------------------------------
    def report(self, stage: str, status: str, detail: str = "") -> None:
        with self._lock:
            s = self.stages.get(stage)
            if s is None or status not in scan_progress.STATUSES:
                return
            if s["status"] in ("done", "skipped") and status in ("pending", "running"):
                return                      # never move backwards
            changed = s["status"] != status
            s["status"] = status
            if detail:
                s["detail"] = detail[:120]
        if changed and status in ("running", "done"):
            print(f"[SCAN {self.id[:6]}]   {s['label']:<22} {status}" + (f"  ({s['detail']})" if s["detail"] and status == "done" else ""),
                  flush=True)

    def _close_stages(self) -> None:
        for s in self.stages.values():
            if s["status"] in ("pending", "running"):
                s["status"] = "skipped" if s["id"] != "verdict" else "done"

    def finish(self, result: Dict[str, Any]) -> None:
        with self._lock:
            self.result = result
            self.state = "done"
            self.finished = time.time()
            self._close_stages()
        shown = str((result or {}).get("display_verdict") or "?")
        print(f"[SCAN {self.id[:6]}] FINISHED  {shown.upper():<30} score {result.get('threat_score', '?')}  "
              f"in {self.finished - self.created:.0f}s  {self.url[:70]}", flush=True)

    def fail(self, message: str) -> None:
        with self._lock:
            self.state = "error"
            self.error = message
            self.finished = time.time()

    def add_watcher(self, user_id: int, source_app: Optional[str]) -> bool:
        """Ask for the scan to be saved to this user's history when it finishes.
        Returns False when the job has already finished (the caller then records it immediately)."""
        with self._lock:
            if self.state != "running":
                return False
            self.watchers.append((user_id, source_app or ""))
            return True

    def release(self) -> None:
        """Wake everyone waiting for this job. Called only after the result is stored, so a caller that wakes up and asks
        again always finds the finished job in the cache."""
        self._event.set()

    def wait(self, timeout: float = JOB_WAIT_SECONDS) -> bool:
        return self._event.wait(timeout)

    # ---- view ---------------------------------------------------------------------------------------------------------
    def progress_percent(self) -> int:
        with self._lock:
            if self.state == "done":
                return 100
            total = sum(STAGE_WEIGHTS.values())
            got = 0.0
            for sid, s in self.stages.items():
                w = STAGE_WEIGHTS.get(sid, 0)
                if s["status"] in ("done", "skipped"):
                    got += w
                elif s["status"] == "running":
                    got += w * 0.35
            return int(min(99, 100 * got / total))

    def snapshot(self, joined: bool = False) -> Dict[str, Any]:
        pct = self.progress_percent()
        with self._lock:
            return {
                "job_id": self.id, "state": self.state, "url": self.url, "progress": pct, "joined": joined,
                "elapsed_seconds": round((self.finished or time.time()) - self.created, 1),
                "stages": [dict(s) for s in self.stages.values()],
                "error": self.error,
            }


class JobManager:
    def __init__(self, runner: Callable[[str], Dict[str, Any]], slots: Optional[threading.BoundedSemaphore] = None,
                 on_finish: Optional[Callable[[ScanJob], None]] = None, cache_max: int = 2000):
        self.runner = runner
        self.slots = slots
        self.on_finish = on_finish
        self.cache_max = cache_max
        self._lock = threading.Lock()
        self._running: Dict[str, ScanJob] = {}
        self._by_id: "OrderedDict[str, ScanJob]" = OrderedDict()
        self._done: "OrderedDict[str, Tuple[float, float, ScanJob]]" = OrderedDict()      # key -> (stored at, ttl, job)

    # ---- public ---------------------------------------------------------------------------------------------------------
    def start_or_join(self, url: str) -> Tuple[ScanJob, str]:
        """Returns (job, how) where how is 'cached' (finished earlier), 'joined' (already running) or 'started'."""
        key = cache_key(url)
        now = time.time()
        with self._lock:
            hit = self._done.get(key)
            if hit and now - hit[0] < hit[1]:
                print(f"[SCAN {hit[2].id[:6]}] CACHED    answered instantly from memory: {url[:80]}", flush=True)
                return hit[2], "cached"
            if hit:
                self._done.pop(key, None)
            running = self._running.get(key)
            if running is not None:
                print(f"[SCAN {running.id[:6]}] JOINED    a second request for the same link attached to the running scan "
                      f"({running.progress_percent()}% done)", flush=True)
                return running, "joined"
            job = ScanJob(key, url)
            self._running[key] = job
            self._remember(job)
        print(f"[SCAN {job.id[:6]}] STARTED   {url[:100]}", flush=True)
        threading.Thread(target=self._run, args=(job,), daemon=True, name=f"scan-{job.id[:6]}").start()
        return job, "started"

    def get(self, job_id: str) -> Optional[ScanJob]:
        with self._lock:
            return self._by_id.get(job_id)

    def clear(self) -> None:
        with self._lock:
            self._done.clear()
            self._running.clear()
            self._by_id.clear()

    # ---- internals -------------------------------------------------------------------------------------------------------
    def _remember(self, job: ScanJob) -> None:
        self._by_id[job.id] = job
        while len(self._by_id) > self.cache_max:
            self._by_id.popitem(last=False)

    def _run(self, job: ScanJob) -> None:
        token = scan_progress.set_sink(job.report)
        acquired = False
        try:
            if self.slots is not None:
                acquired = self.slots.acquire(timeout=20)
                if not acquired:
                    job.fail("The analysis service is busy. Please try again.")
                    return
            result = self.runner(job.url)
            if not isinstance(result, dict):
                job.fail("The analysis returned no result.")
                return
            job.finish(result)
            self._store(job)
        except Exception as exc:       # a failing scan must never leave a job hanging
            logger.exception("scan job failed for %s", job.url[:80])
            job.fail(f"The analysis failed ({type(exc).__name__}).")
        finally:
            if acquired and self.slots is not None:
                self.slots.release()
            scan_progress.reset_sink(token)
            with self._lock:
                self._running.pop(job.key, None)
            job.release()
            if self.on_finish is not None and job.state == "done":
                try:
                    self.on_finish(job)
                except Exception:
                    logger.exception("scan job finish hook failed")

    def _store(self, job: ScanJob) -> None:
        shown = str((job.result or {}).get("display_verdict") or "")
        if shown == "Dangerous":
            ttl = TTL_DANGEROUS
        elif shown == "Safe":
            ttl = TTL_SAFE
        else:
            ttl = TTL_UNVERIFIED
        with self._lock:
            self._done[job.key] = (time.time(), ttl, job)
            while len(self._done) > self.cache_max:
                self._done.popitem(last=False)

    def result_copy(self, job: ScanJob) -> Optional[Dict[str, Any]]:
        return copy.deepcopy(job.result) if job.result is not None else None
