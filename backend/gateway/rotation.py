"""
Sender-IP rotation: "the attacker keeps switching IP addresses".

One forged email from one unauthorised address is a spoofing attempt. The SAME claimed sender domain arriving from several
different unauthorised addresses within minutes is a campaign that rotates its sending infrastructure to dodge IP blocks.
We cannot find the person; we can see the pattern, and block the pattern (the claimed domain + failed checks) instead of one IP.
"""
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional

WINDOW_SECONDS = 600          # look back 10 minutes
MIN_DISTINCT_IPS = 3          # this many different failing addresses claiming one domain = rotation


class RotationTracker:
    def __init__(self, window: float = WINDOW_SECONDS, minimum: int = MIN_DISTINCT_IPS):
        self.window, self.minimum = window, minimum
        self._events: Dict[str, List[tuple]] = defaultdict(list)       # claimed domain -> [(time, ip)]
        self._lock = threading.Lock()

    def record(self, claimed_domain: str, ip: str, failed: bool, now: Optional[float] = None) -> Dict[str, Any]:
        """Note one message. Only messages whose sender checks FAILED count towards rotation (a real sender's own IPs do not)."""
        now = time.time() if now is None else now
        domain = (claimed_domain or "").lower()
        with self._lock:
            if domain and ip and failed:
                self._events[domain].append((now, ip))
            fresh = [(t, i) for t, i in self._events.get(domain, []) if now - t <= self.window]
            if domain in self._events:
                self._events[domain] = fresh
            ips = list(dict.fromkeys(i for _, i in fresh))
        rotating = len(ips) >= self.minimum
        return {"claimed_domain": domain, "failing_ips": ips, "distinct_ips": len(ips), "rotating": rotating,
                "message": (f"{len(ips)} different unauthorised addresses claimed to be {domain} within "
                            f"{int(self.window // 60)} minutes: the sender is rotating addresses. Block the pattern, not one IP.")
                if rotating else ""}
