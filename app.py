"""KubePulse - a small read-only Kubernetes dashboard.

No third-party dependencies. Runs in-cluster using its service account,
or locally against `kubectl proxy` (set K8S_API=http://127.0.0.1:8001).

One background thread polls the cluster every POLL_SECONDS and keeps the result
in memory, so browsers never cause Kubernetes API calls for the dashboard view.
The same loop keeps a few hours of trend history and sends Mattermost alerts.
"""
import gzip
import hashlib
import json
import os
import re
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

env = os.getenv
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")
PORT = int(env("PORT", "8080"))
POLL_SECONDS = max(5, int(env("POLL_SECONDS", "20")))
HISTORY_POINTS = int(env("HISTORY_POINTS", "540"))  # 3 hours at 20s
# Optional comma-separated namespace allowlist; empty = all namespaces
NAMESPACES = [n.strip() for n in env("NAMESPACES", "").split(",") if n.strip()]
CLUSTER_NAME = env("CLUSTER_NAME", "").strip()

INDEX_HTML = (Path(__file__).parent / "index.html").read_bytes()
INDEX_GZ = gzip.compress(INDEX_HTML, 9)

# Optional AI investigation via any OpenAI-compatible chat completions API
OPENAI_API_KEY = env("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = env("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = env("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
AI_MAX_STEPS = int(env("AI_MAX_STEPS", "8"))

# Optional Mattermost alerts
MATTERMOST_WEBHOOK_URL = env("MATTERMOST_WEBHOOK_URL", "").strip()
DASHBOARD_URL = env("DASHBOARD_URL", "").strip().rstrip("/")
ALERT_PENDING = int(env("ALERT_PENDING_MINUTES", "3")) * 60
ALERT_COOLDOWN = int(env("ALERT_COOLDOWN_MINUTES", "30")) * 60
ALERT_RESOLVED = env("ALERT_RESOLVED", "true").lower() == "true"
CERT_WARN_DAYS = int(env("CERT_WARN_DAYS", "14"))
PVC_WARN_PERCENT = int(env("PVC_WARN_PERCENT", "85"))

# Trend data (restart timeline, daily uptime) survives container restarts here
DATA_DIR = Path(env("DATA_DIR", "/data"))
# Disk usage per PVC needs the kubelet stats API (RBAC: nodes/proxy). Off by default.
PVC_STATS = env("PVC_STATS", "false").lower() == "true"


# ---------- Kubernetes API access ----------

def _api_config():
    override = env("K8S_API")
    if override:
        return override.rstrip("/"), None, None
    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    ctx = ssl.create_default_context(cafile=str(SA_DIR / "ca.crt"))
    return f"https://{host}:{port}", ctx, SA_DIR / "token"


BASE_URL, SSL_CTX, TOKEN_PATH = _api_config()


def _k8s_open(path):
    req = urllib.request.Request(BASE_URL + path)
    if TOKEN_PATH:
        # Re-read each time: projected tokens rotate
        req.add_header("Authorization", "Bearer " + TOKEN_PATH.read_text().strip())
    return urllib.request.urlopen(req, context=SSL_CTX, timeout=10)


def k8s_get(path):
    with _k8s_open(path) as resp:
        return json.load(resp)


def k8s_get_text(path):
    with _k8s_open(path) as resp:
        return resp.read().decode("utf-8", "replace")


def k8s_get_optional(path):
    try:
        return k8s_get(path)
    except Exception:
        return None  # metrics-server missing, or no permission


def k8s_list(path):
    """List from the API server's watch cache (resourceVersion=0): much cheaper for the cluster."""
    return k8s_get(path + ("&" if "?" in path else "?") + "resourceVersion=0")


def post_json(url, body, headers=None, timeout=10):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        return json.loads(raw) if raw.strip().startswith(b"{") else None


# ---------- Quantities and time ----------

_CPU_SUFFIX = {"n": 1e-9, "u": 1e-6, "m": 1e-3}
_MEM_SUFFIX = {
    "Ki": 1024, "Mi": 1024**2, "Gi": 1024**3, "Ti": 1024**4,
    "K": 1e3, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12,
}


def parse_cpu(q):
    """Return cores as float."""
    if not q:
        return 0.0
    q = str(q)
    if q[-1] in _CPU_SUFFIX:
        return float(q[:-1]) * _CPU_SUFFIX[q[-1]]
    return float(q)


def parse_mem(q):
    """Return bytes as float."""
    if not q:
        return 0.0
    q = str(q)
    for suffix in ("Ki", "Mi", "Gi", "Ti"):
        if q.endswith(suffix):
            return float(q[:-2]) * _MEM_SUFFIX[suffix]
    if q[-1] in _MEM_SUFFIX:
        return float(q[:-1]) * _MEM_SUFFIX[q[-1]]
    return float(q)


def age_seconds(ts):
    if not ts:
        return None
    # Tolerate fractional seconds (event eventTime uses microseconds)
    created = datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    return int((datetime.now(timezone.utc) - created).total_seconds())


def fmt_age(s):
    if s is None:
        return "?"
    return f"{s}s" if s < 120 else f"{s // 60}m" if s < 7200 else f"{s // 3600}h" if s < 172800 else f"{s // 86400}d"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- Shaping data ----------

def pod_status(pod):
    """Approximate the STATUS column of `kubectl get pods`."""
    meta, status = pod["metadata"], pod.get("status", {})
    if meta.get("deletionTimestamp"):
        return "Terminating"
    reason = status.get("reason") or status.get("phase", "Unknown")
    for cs in status.get("initContainerStatuses", []) or []:
        state = cs.get("state", {})
        if "waiting" in state and state["waiting"].get("reason") not in (None, "PodInitializing"):
            return "Init:" + state["waiting"]["reason"]
        if "terminated" in state and state["terminated"].get("exitCode", 0) != 0:
            return "Init:Error"
    for cs in status.get("containerStatuses", []) or []:
        state = cs.get("state", {})
        if "waiting" in state and state["waiting"].get("reason"):
            reason = state["waiting"]["reason"]
        elif "terminated" in state and state["terminated"].get("reason"):
            reason = state["terminated"]["reason"]
    return reason


WAIT_STATES = {"Pending", "ContainerCreating", "PodInitializing"}


def triage(status, ready, total, last_exit_age, last_reason, phase="", owner=""):
    """Return (level, kind, short reason) for a pod. level is ok / warn / bad."""
    if phase == "Failed" and (status == "Evicted" or owner.startswith(("Job/", "CronJob/"))):
        # Finished pods Kubernetes keeps around: a replacement or the next run already took over
        return "warn", "finished", "Evicted, replaced by a new pod" if status == "Evicted" else f"Job run failed ({status})"
    if status in ("Running", "Succeeded", "Completed", "Terminating"):
        if status == "Running" and ready < total:
            return "warn", "notready", "Running but not ready"
        if status == "Running" and last_exit_age is not None and last_exit_age < 3600:
            # Recovered and ready: worth showing, but it doesn't count against cluster health
            return "ok", "restarted", f"Restarted {fmt_age(last_exit_age)} ago" + (f" ({last_reason})" if last_reason else "")
        return "ok", None, None
    if status in WAIT_STATES:
        return "warn", "pending", status
    extra = f" · last exit {last_reason}" if last_reason and last_reason != status else ""
    return "bad", "failing", status + extra


def pod_owner(meta):
    """The workload that owns a pod, e.g. "Deployment/payments-api". ReplicaSets are mapped to their Deployment."""
    ref = next(iter(meta.get("ownerReferences") or []), None)
    if not ref:
        return ""
    kind, name = ref["kind"], ref["name"]
    tmpl_hash = (meta.get("labels") or {}).get("pod-template-hash")
    if kind == "ReplicaSet" and tmpl_hash and name.endswith("-" + tmpl_hash):
        kind, name = "Deployment", name[: -len(tmpl_hash) - 1]
    return f"{kind}/{name}"


def pod_row(p, usage=(None, None)):
    meta, spec, status = p["metadata"], p.get("spec", {}), p.get("status", {})
    cstat = status.get("containerStatuses", []) or []
    containers = spec.get("containers", [])
    last = max((c["lastState"]["terminated"] for c in cstat if c.get("lastState", {}).get("terminated")),
               key=lambda t: t.get("finishedAt") or "", default=None)
    last_reason = last.get("reason") if last else None
    last_exit_age = age_seconds(last.get("finishedAt")) if last else None
    ready = sum(1 for c in cstat if c.get("ready"))
    st = pod_status(p)
    owner = pod_owner(meta)
    level, kind, attention = triage(st, ready, len(containers), last_exit_age, last_reason, status.get("phase", ""), owner)
    ready_cond = next((c for c in status.get("conditions", []) or [] if c.get("type") == "Ready"), None)
    return {
        "namespace": meta["namespace"],
        "name": meta["name"],
        "owner": owner,
        "status": st,
        "ready": f"{ready}/{len(containers)}",
        "restarts": sum(c.get("restartCount", 0) for c in cstat),
        "age": age_seconds(meta.get("creationTimestamp")),
        "node": spec.get("nodeName") or "",
        "cpu": usage[0],
        "mem": usage[1],
        "memLimit": sum(parse_mem(c.get("resources", {}).get("limits", {}).get("memory")) for c in containers) or None,
        "cpuReq": sum(parse_cpu(c.get("resources", {}).get("requests", {}).get("cpu")) for c in containers) or None,
        "memReq": sum(parse_mem(c.get("resources", {}).get("requests", {}).get("memory")) for c in containers) or None,
        "lastReason": last_reason,
        "lastExitAge": last_exit_age,
        "level": level,
        "kind": kind,
        "attention": attention,
        # How long the pod has been in its current ready / not-ready state
        "stateAge": age_seconds(ready_cond.get("lastTransitionTime")) if ready_cond else age_seconds(meta.get("creationTimestamp")),
    }


def build_snapshot():
    if NAMESPACES:
        pods = []
        for ns in NAMESPACES:
            pods += k8s_list(f"/api/v1/namespaces/{ns}/pods")["items"]
    else:
        pods = k8s_list("/api/v1/pods")["items"]
    nodes = k8s_list("/api/v1/nodes")["items"]

    node_metrics = k8s_get_optional("/apis/metrics.k8s.io/v1beta1/nodes")
    pod_metrics = k8s_get_optional("/apis/metrics.k8s.io/v1beta1/pods")
    node_usage = {m["metadata"]["name"]: m["usage"] for m in (node_metrics or {}).get("items", [])}
    pod_usage = {}
    for m in (pod_metrics or {}).get("items", []):
        pod_usage[(m["metadata"]["namespace"], m["metadata"]["name"])] = (
            sum(parse_cpu(c["usage"].get("cpu")) for c in m.get("containers", [])),
            sum(parse_mem(c["usage"].get("memory")) for c in m.get("containers", [])),
        )

    pod_rows = [pod_row(p, pod_usage.get((p["metadata"]["namespace"], p["metadata"]["name"]), (None, None))) for p in pods]
    pods_per_node = {}
    for r in pod_rows:
        pods_per_node[r["node"]] = pods_per_node.get(r["node"], 0) + 1

    node_rows = []
    cluster = {"cpu": 0.0, "cpuAlloc": 0.0, "mem": 0.0, "memAlloc": 0.0}
    for n in nodes:
        meta, status = n["metadata"], n.get("status", {})
        labels = meta.get("labels", {})
        conds = status.get("conditions", [])
        alloc = status.get("allocatable", {})
        usage = node_usage.get(meta["name"], {})
        roles = [k.split("/", 1)[1] for k in labels if k.startswith("node-role.kubernetes.io/")]
        row = {
            "name": meta["name"],
            "ready": next((c["status"] == "True" for c in conds if c["type"] == "Ready"), False),
            "pressure": [c["type"] for c in conds if c["type"] != "Ready" and c["status"] == "True"],
            "schedulable": not n.get("spec", {}).get("unschedulable", False),
            "roles": ",".join(roles) or labels.get("agentpool") or labels.get("eks.amazonaws.com/nodegroup") or "",
            "version": status.get("nodeInfo", {}).get("kubeletVersion", ""),
            "age": age_seconds(meta.get("creationTimestamp")),
            "cpu": parse_cpu(usage["cpu"]) if usage else None,
            "cpuAlloc": parse_cpu(alloc.get("cpu")),
            "mem": parse_mem(usage["memory"]) if usage else None,
            "memAlloc": parse_mem(alloc.get("memory")),
            "pods": pods_per_node.get(meta["name"], 0),
            "podsAlloc": int(alloc.get("pods", 0)),
        }
        if usage:
            cluster["cpu"] += row["cpu"]; cluster["cpuAlloc"] += row["cpuAlloc"]
            cluster["mem"] += row["mem"]; cluster["memAlloc"] += row["memAlloc"]
        node_rows.append(row)

    return {
        "generatedAt": now_iso(),
        "pollSeconds": POLL_SECONDS,
        "clusterName": CLUSTER_NAME,
        "metricsAvailable": node_metrics is not None and pod_metrics is not None,
        "cluster": cluster if cluster["cpuAlloc"] else None,
        "nodes": sorted(node_rows, key=lambda r: r["name"]),
        "pods": sorted(pod_rows, key=lambda r: (r["namespace"], r["name"])),
        "warnings": recent_warnings(),
        "aiEnabled": bool(OPENAI_API_KEY),
    }


# ---------- Trend history (in memory, a few KB) ----------

HISTORY = deque(maxlen=HISTORY_POINTS)   # [t, cpu%, mem%, running, attention, restarts]
NODE_HISTORY = {}                        # node -> deque of (cpu%, mem%), last 30 minutes


def _pct(used, total):
    return round(used / total * 100, 1) if used is not None and total else None


def record_history(snap):
    c = snap["cluster"] or {}
    pods = snap["pods"]
    HISTORY.append([
        int(time.time()),
        _pct(c.get("cpu"), c.get("cpuAlloc")),
        _pct(c.get("mem"), c.get("memAlloc")),
        sum(1 for p in pods if p["status"] == "Running"),
        sum(1 for p in pods if p["level"] != "ok"),
        sum(p["restarts"] for p in pods),
    ])
    seen = set()
    for n in snap["nodes"]:
        seen.add(n["name"])
        dq = NODE_HISTORY.setdefault(n["name"], deque(maxlen=max(10, 1800 // POLL_SECONDS)))
        dq.append((_pct(n["cpu"], n["cpuAlloc"]), _pct(n["mem"], n["memAlloc"])))
        n["hist"] = {"cpu": [x[0] for x in dq], "mem": [x[1] for x in dq]}
    for name in set(NODE_HISTORY) - seen:
        del NODE_HISTORY[name]
    cols = list(zip(*HISTORY))
    snap["history"] = dict(zip(("t", "cpu", "mem", "running", "attention", "restarts"), map(list, cols)))


# ---------- Insights: restart timeline, uptime, waste, churn, certificates, PVCs ----------

def _day(ts):
    return time.strftime("%Y-%m-%d", time.localtime(ts))


class Insights:
    BUCKET = 900            # restart timeline: 15-minute buckets over 24 hours
    SLOW_EVERY = 300        # certificates and PVCs change slowly: refresh every 5 minutes

    def __init__(self):
        self.timeline = {}   # bucket start -> [restarts, crashes, oomkills]
        self.days = {}       # "YYYY-MM-DD" -> [sum of healthy %, samples]
        self.usage = {}      # (ns, pod) -> [cpu average, memory peak, samples]
        self.created = {}    # (ns, owner) -> {pod: created at}
        self.ended = {}      # (ns, owner) -> [(created at, ended at)]
        self.prev = None     # (ns, pod) -> (restarts, level)
        self.certs = self.pvcs = None
        self.slow_at = self.saved_at = 0.0
        self._load()

    # Persistence: only the small trend data, so a restart doesn't wipe the timeline and uptime
    def _load(self):
        try:
            state = json.loads((DATA_DIR / "state.json").read_text())
            self.timeline = {int(k): v for k, v in state.get("timeline", {}).items()}
            self.days = state.get("days", {})
            keep_after = time.time() - HISTORY_POINTS * POLL_SECONDS
            HISTORY.extend(h for h in state.get("history", []) if h[0] > keep_after)
        except Exception:
            pass

    def _save(self):
        try:
            tmp = DATA_DIR / "state.json.tmp"
            tmp.write_text(json.dumps({"timeline": self.timeline, "days": self.days, "history": list(HISTORY)}))
            tmp.replace(DATA_DIR / "state.json")
        except Exception:
            pass  # no writable volume: keep it in memory only

    def update(self, snap):
        now = time.time()
        pods = snap["pods"]
        cur = {(p["namespace"], p["name"]): p for p in pods}
        bucket = self.timeline.setdefault(int(now // self.BUCKET * self.BUCKET), [0, 0, 0])

        if self.prev is None:
            if not self.timeline or sum(sum(v) for v in self.timeline.values()) == 0:
                # First run: backfill from each pod's last termination time
                for p in pods:
                    if p["lastExitAge"] is not None and p["lastExitAge"] < 86400:
                        b = self.timeline.setdefault(int((now - p["lastExitAge"]) // self.BUCKET * self.BUCKET), [0, 0, 0])
                        b[0] += 1
                        b[2] += p["lastReason"] == "OOMKilled"
        else:
            for k, p in cur.items():
                prev = self.prev.get(k)
                delta = p["restarts"] - prev[0] if prev else 0
                if delta > 0:
                    bucket[0] += delta
                    if p["lastReason"] == "OOMKilled":
                        bucket[2] += delta
                if p["level"] == "bad" and (not prev or prev[1] != "bad"):
                    bucket[1] += 1
        self.prev = {k: (p["restarts"], p["level"]) for k, p in cur.items()}
        cutoff = now - 86400
        self.timeline = {k: v for k, v in self.timeline.items() if k >= cutoff - self.BUCKET}

        healthy = (len(pods) - sum(1 for p in pods if p["level"] != "ok")) / len(pods) * 100 if pods else 100.0
        day = self.days.setdefault(_day(now), [0.0, 0])
        day[0] += healthy
        day[1] += 1
        for d in sorted(self.days)[:-8]:
            del self.days[d]

        # Usage per pod: CPU as a moving average, memory as the peak seen
        for k, p in cur.items():
            if p["cpu"] is None:
                continue
            u = self.usage.get(k)
            if u is None:
                self.usage[k] = [p["cpu"], p["mem"], 1]
            else:
                u[0] = u[0] * 0.95 + p["cpu"] * 0.05
                u[1] = max(u[1], p["mem"])
                u[2] += 1
        for k in set(self.usage) - set(cur):
            del self.usage[k]

        # Pod churn per workload: which pods were created, and how long ended ones lived
        for p in pods:
            if p["owner"] and p["age"] is not None:
                self.created.setdefault((p["namespace"], p["owner"]), {}).setdefault(p["name"], now - p["age"])
        for okey, names in list(self.created.items()):
            for name, born in list(names.items()):
                if (okey[0], name) not in cur:
                    self.ended.setdefault(okey, []).append((born, now))
                    del names[name]
            if not names:
                del self.created[okey]
        for okey in list(self.ended):
            self.ended[okey] = [e for e in self.ended[okey] if e[1] > cutoff]
            if not self.ended[okey]:
                del self.ended[okey]

        if now - self.slow_at > self.SLOW_EVERY:
            self.slow_at = now
            self.certs = cert_rows()
            self.pvcs = pvc_rows(snap["nodes"])
        if now - self.saved_at > 120:
            self.saved_at = now
            self._save()

        snap["insights"] = {
            "timeline": self._timeline(now),
            "uptime": [{"day": d, "score": round(s / n, 2)} for d, (s, n) in sorted(self.days.items())[-7:]],
            "waste": self._waste(pods),
            "churn": self._churn(pods, now),
        }
        snap["certs"] = self.certs
        snap["pvcs"] = self.pvcs
        snap["pvcStats"] = PVC_STATS

    def _timeline(self, now):
        start = int((now - 86400) // self.BUCKET * self.BUCKET) + self.BUCKET
        keys = range(start, start + 96 * self.BUCKET, self.BUCKET)
        cols = [self.timeline.get(k, [0, 0, 0]) for k in keys]
        return {"start": start, "bucketSeconds": self.BUCKET,
                "restarts": [c[0] for c in cols], "crashes": [c[1] for c in cols], "oomkills": [c[2] for c in cols]}

    def _waste(self, pods):
        """Workloads whose requests are far above what their pods actually use."""
        groups = {}
        for p in pods:
            u = self.usage.get((p["namespace"], p["name"]))
            if not u or u[2] < 15 or p["status"] != "Running":   # need ~5 minutes of samples
                continue
            g = groups.setdefault((p["namespace"], p["owner"] or "Pod/" + p["name"]),
                                  {"pods": 0, "cpuReq": 0.0, "cpuUsed": 0.0, "memReq": 0.0, "memPeak": 0.0})
            g["pods"] += 1
            g["cpuReq"] += p["cpuReq"] or 0
            g["cpuUsed"] += u[0]
            g["memReq"] += p["memReq"] or 0
            g["memPeak"] += u[1] or 0
        rows = []
        for (ns, owner), g in groups.items():
            cpu_waste = g["cpuReq"] - g["cpuUsed"] if g["cpuReq"] > 2.5 * g["cpuUsed"] else 0
            mem_waste = g["memReq"] - g["memPeak"] if g["memReq"] > 2 * g["memPeak"] else 0
            cpu_waste = cpu_waste if cpu_waste >= 0.1 else 0
            mem_waste = mem_waste if mem_waste >= 128 * 1024**2 else 0
            if cpu_waste or mem_waste:
                n = g["pods"]
                rows.append({
                    "namespace": ns, "owner": owner, "pods": n,
                    "cpuReq": g["cpuReq"] / n, "cpuUsed": g["cpuUsed"] / n,
                    "memReq": g["memReq"] / n, "memPeak": g["memPeak"] / n,
                    "cpuWaste": cpu_waste, "memWaste": mem_waste,
                    # Suggested request per pod: comfortable headroom over what is really used
                    "cpuSuggest": max(0.01, g["cpuUsed"] / n * 1.5), "memSuggest": max(32 * 1024**2, g["memPeak"] / n * 1.3),
                })
        rows.sort(key=lambda r: r["cpuWaste"] + r["memWaste"] / 1024**3 / 4, reverse=True)
        return rows[:15]

    def _churn(self, pods, now):
        """Workloads that keep replacing their pods, even if the current ones look fine."""
        current = {}
        for p in pods:
            if p["owner"]:
                current[(p["namespace"], p["owner"])] = current.get((p["namespace"], p["owner"]), 0) + 1
        rows = []
        for okey in set(self.created) | set(self.ended):
            if okey[1].startswith("Job/"):
                continue
            ended = [e for e in self.ended.get(okey, []) if e[0] > now - 86400]
            born = [t for t in self.created.get(okey, {}).values() if t > now - 86400]
            made = len(ended) + len(born)
            replicas = current.get(okey, 0)
            if made >= max(4, 2 * replicas + 2):
                lives = sorted(e[1] - e[0] for e in ended)
                rows.append({"namespace": okey[0], "owner": okey[1], "replicas": replicas, "created24h": made,
                             "medianLife": int(lives[len(lives) // 2]) if lives else None})
        rows.sort(key=lambda r: r["created24h"], reverse=True)
        return rows[:10]


def cert_rows():
    """cert-manager Certificates with days until expiry. None when cert-manager isn't installed or readable."""
    paths = [f"/apis/cert-manager.io/v1/namespaces/{ns}/certificates" for ns in NAMESPACES] or ["/apis/cert-manager.io/v1/certificates"]
    items = []
    for path in paths:
        res = k8s_get_optional(path)
        if res is None:
            return None
        items += res.get("items", [])
    rows = []
    for c in items:
        st = c.get("status", {})
        not_after = st.get("notAfter")
        left = -age_seconds(not_after) if not_after else None
        rows.append({
            "namespace": c["metadata"]["namespace"], "name": c["metadata"]["name"],
            "dnsNames": (c.get("spec", {}).get("dnsNames") or [])[:3], "secret": c.get("spec", {}).get("secretName"),
            "notAfter": not_after, "daysLeft": None if left is None else round(left / 86400, 1),
            "ready": next((x["status"] == "True" for x in st.get("conditions", []) if x["type"] == "Ready"), False),
        })
    return sorted(rows, key=lambda r: r["daysLeft"] if r["daysLeft"] is not None else -1)


def pvc_rows(nodes):
    """PersistentVolumeClaims, with disk usage from the kubelet when PVC_STATS is on."""
    paths = [f"/api/v1/namespaces/{ns}/persistentvolumeclaims" for ns in NAMESPACES] or ["/api/v1/persistentvolumeclaims"]
    claims = []
    for path in paths:
        try:
            claims += k8s_list(path)["items"]
        except Exception:
            return None
    usage = {}
    if PVC_STATS:
        for n in nodes:
            if not n["ready"]:
                continue
            stats = k8s_get_optional(f"/api/v1/nodes/{n['name']}/proxy/stats/summary")
            for pod in (stats or {}).get("pods", []):
                for v in pod.get("volume", []) or []:
                    ref = v.get("pvcRef")
                    if ref and v.get("capacityBytes"):
                        usage[(ref["namespace"], ref["name"])] = (v.get("usedBytes") or 0, v["capacityBytes"], pod["podRef"]["name"])
    rows = []
    for c in claims:
        key = (c["metadata"]["namespace"], c["metadata"]["name"])
        used, cap, pod = usage.get(key, (None, None, None))
        rows.append({
            "namespace": key[0], "name": key[1], "phase": c.get("status", {}).get("phase"),
            "size": (c.get("status", {}).get("capacity") or {}).get("storage") or c["spec"].get("resources", {}).get("requests", {}).get("storage"),
            "storageClass": c["spec"].get("storageClassName"), "used": used, "capacity": cap, "pod": pod,
            "percent": round(used / cap * 100, 1) if cap else None,
        })
    return sorted(rows, key=lambda r: (r["phase"] == "Bound", -(r["percent"] or 0)))


INSIGHTS = Insights()


# ---------- Events, pod detail and logs ----------

NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")


class BadRequest(Exception):
    pass


def check_name(v, what="name"):
    v = str(v or "")
    if not NAME_RE.match(v):
        raise BadRequest(f"invalid {what}: {v!r}")
    return v


def check_ns(v):
    v = check_name(v, "namespace")
    if NAMESPACES and v not in NAMESPACES:
        raise BadRequest("namespace is not in the KubePulse allowlist")
    return v


def event_row(e):
    obj, meta = e.get("involvedObject", {}), e.get("metadata", {})
    return {
        "type": e.get("type") or "Normal",
        "reason": e.get("reason") or "",
        "message": (e.get("message") or "").strip(),
        "count": e.get("count") or (e.get("series") or {}).get("count") or 1,
        "age": age_seconds(e.get("lastTimestamp") or e.get("eventTime") or meta.get("creationTimestamp")),
        "namespace": obj.get("namespace") or meta.get("namespace") or "",
        "kind": obj.get("kind") or "",
        "name": obj.get("name") or "",
    }


def newest_first(rows):
    return sorted(rows, key=lambda r: r["age"] if r["age"] is not None else float("inf"))


def recent_warnings(limit=60):
    """Latest Warning events. None when the service account can't read events."""
    sel = "?fieldSelector=" + quote("type=Warning")
    paths = [f"/api/v1/namespaces/{ns}/events{sel}" for ns in NAMESPACES] or [f"/api/v1/events{sel}"]
    items = []
    for path in paths:
        try:
            items += k8s_list(path)["items"]
        except Exception:
            return None
    return newest_first(event_row(e) for e in items)[:limit]


def container_state(state):
    for phase in ("running", "waiting", "terminated"):
        if phase in (state or {}):
            s = state[phase] or {}
            return {
                "phase": phase,
                "reason": s.get("reason") or phase.capitalize(),
                "message": s.get("message"),
                "exitCode": s.get("exitCode"),
                "age": age_seconds(s.get("finishedAt") if phase == "terminated" else s.get("startedAt")),
            }
    return {"phase": "unknown", "reason": "Unknown"}


def _probe(p):
    if not p:
        return None
    if "httpGet" in p:
        what = f'HTTP GET {p["httpGet"].get("path", "/")} on port {p["httpGet"].get("port")}'
    elif "tcpSocket" in p:
        what = f'TCP port {p["tcpSocket"].get("port")}'
    elif "exec" in p:
        what = "exec " + " ".join(p["exec"].get("command", []))[:120]
    elif "grpc" in p:
        what = f'gRPC port {p["grpc"].get("port")}'
    else:
        what = "probe"
    return (f'{what} (delay {p.get("initialDelaySeconds", 0)}s, every {p.get("periodSeconds", 10)}s, '
            f'timeout {p.get("timeoutSeconds", 1)}s, fails after {p.get("failureThreshold", 3)})')


def _config_refs(c):
    refs = []
    for ef in c.get("envFrom", []) or []:
        if "configMapRef" in ef:
            refs.append("configMap:" + ef["configMapRef"]["name"])
        if "secretRef" in ef:
            refs.append("secret:" + ef["secretRef"]["name"])
    for e in c.get("env", []) or []:
        vf = e.get("valueFrom") or {}
        if "configMapKeyRef" in vf:
            refs.append(f'configMap:{vf["configMapKeyRef"]["name"]}/{vf["configMapKeyRef"]["key"]}')
        if "secretKeyRef" in vf:
            refs.append(f'secret:{vf["secretKeyRef"]["name"]}/{vf["secretKeyRef"]["key"]}')
    return refs


def container_spec(c):
    res = c.get("resources", {})
    return {
        "name": c["name"],
        "image": c.get("image", ""),
        "command": (c.get("command") or [])[:6],
        "args": (c.get("args") or [])[:10],
        "ports": [x.get("containerPort") for x in c.get("ports", []) or []],
        "requests": res.get("requests", {}),
        "limits": res.get("limits", {}),
        "liveness": _probe(c.get("livenessProbe")),
        "readiness": _probe(c.get("readinessProbe")),
        "startup": _probe(c.get("startupProbe")),
        "envNames": [e["name"] for e in c.get("env", []) or []][:40],
        "configRefs": _config_refs(c),
    }


def _volumes(spec):
    out = []
    for v in spec.get("volumes", []) or []:
        for kind, key in (("configMap", "name"), ("secret", "secretName"), ("persistentVolumeClaim", "claimName")):
            if kind in v:
                out.append({"name": v["name"], "type": kind, "ref": v[kind].get(key)})
                break
        else:
            out.append({"name": v["name"], "type": next((k for k in v if k != "name"), "unknown")})
    return out


def current_usage(ns, name):
    snap = STORE.snap or {}
    return next(((p["cpu"], p["mem"]) for p in snap.get("pods", []) if p["namespace"] == ns and p["name"] == name), (None, None))


def pod_detail(ns, name):
    pod = k8s_get(f"/api/v1/namespaces/{ns}/pods/{name}")
    meta, spec, status = pod["metadata"], pod.get("spec", {}), pod.get("status", {})
    statuses = {c["name"]: c for c in (status.get("initContainerStatuses") or []) + (status.get("containerStatuses") or [])}
    containers = []
    for init, c in [(True, c) for c in spec.get("initContainers", [])] + [(False, c) for c in spec.get("containers", [])]:
        cs = statuses.get(c["name"], {})
        containers.append({
            **container_spec(c),
            "init": init,
            "ready": cs.get("ready", False),
            "restarts": cs.get("restartCount", 0),
            "state": container_state(cs.get("state")),
            "last": container_state(cs["lastState"]) if cs.get("lastState", {}).get("terminated") else None,
        })
    sel = quote(f"involvedObject.kind=Pod,involvedObject.name={name}")
    events = k8s_get_optional(f"/api/v1/namespaces/{ns}/events?fieldSelector={sel}")
    cpu, mem = current_usage(ns, name)
    return {
        "namespace": ns,
        "name": name,
        "status": pod_status(pod),
        "node": spec.get("nodeName") or "",
        "ip": status.get("podIP") or "",
        "qos": status.get("qosClass") or "",
        "age": age_seconds(meta.get("creationTimestamp")),
        "owner": next((f'{o["kind"]}/{o["name"]}' for o in meta.get("ownerReferences", [])), ""),
        "labels": meta.get("labels", {}),
        "conditions": [{k: c.get(k) for k in ("type", "status", "reason", "message")} for c in status.get("conditions", []) or []],
        "volumes": _volumes(spec),
        "usage": {"cpu": cpu, "mem": mem},
        "containers": containers,
        "events": None if events is None else newest_first(event_row(e) for e in events["items"]),
    }


def pod_logs(ns, name, container, previous, tail=100):
    qs = f"container={quote(container)}&tailLines={tail}&limitBytes=262144" + ("&previous=true" if previous else "")
    return k8s_get_text(f"/api/v1/namespaces/{ns}/pods/{name}/log?{qs}")


def api_error(e):
    """Map an exception to (HTTP code, message), keeping the upstream API's own message."""
    if isinstance(e, BadRequest):
        return 400, str(e)
    if isinstance(e, urllib.error.HTTPError):
        try:
            err = json.loads(e.read())
            # Kubernetes puts it in "message", OpenAI in "error.message"
            return e.code, err.get("message") or (err.get("error") or {}).get("message") or str(e)
        except Exception:
            return e.code, str(e)
    return 502, str(e)


# ---------- AI investigation: an agent loop over read-only tools ----------

# Scrub obvious secrets before anything leaves the cluster
_REDACT = [
    (re.compile(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)(\"?\s*[=:]\s*\"?)[^\s,;\"']+"), r"\1\2[REDACTED]"),
    (re.compile(r"\b(sk-[a-zA-Z0-9_-]{16,}|AKIA[0-9A-Z]{16}|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]+)"), "[REDACTED]"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s]+@"), r"\1[REDACTED]@"),
]


def redact(text):
    for pattern, repl in _REDACT:
        text = pattern.sub(repl, text)
    return text


WORKLOAD_PATHS = {
    "Deployment": "/apis/apps/v1/namespaces/{ns}/deployments/{name}",
    "ReplicaSet": "/apis/apps/v1/namespaces/{ns}/replicasets/{name}",
    "StatefulSet": "/apis/apps/v1/namespaces/{ns}/statefulsets/{name}",
    "DaemonSet": "/apis/apps/v1/namespaces/{ns}/daemonsets/{name}",
    "Job": "/apis/batch/v1/namespaces/{ns}/jobs/{name}",
    "CronJob": "/apis/batch/v1/namespaces/{ns}/cronjobs/{name}",
}
SELECTOR_RE = re.compile(r"^[\w./=,!() -]{0,250}$")


def tool_get_pod(namespace, name):
    d = pod_detail(check_ns(namespace), check_name(name))
    d["events"] = (d["events"] or [])[:15]
    return d, f"{d['status']}, {sum(c['restarts'] for c in d['containers'])} restarts"


def tool_get_pod_logs(namespace, name, container, previous=False, tail_lines=150):
    tail = max(20, min(int(tail_lines or 150), 300))
    text = pod_logs(check_ns(namespace), check_name(name), check_name(container, "container"), bool(previous), tail)
    return {"logs": text[-12000:]}, f"{text.count(chr(10))} lines"


def tool_get_events(namespace, name=""):
    ns = check_ns(namespace)
    sel = quote(f"involvedObject.name={check_name(name)}") if name else quote("type=Warning")
    rows = newest_first(event_row(e) for e in k8s_get(f"/api/v1/namespaces/{ns}/events?fieldSelector={sel}")["items"])[:30]
    return {"events": rows}, f"{len(rows)} events"


def tool_get_workload(namespace, kind, name):
    if kind not in WORKLOAD_PATHS:
        raise BadRequest(f"kind must be one of {', '.join(WORKLOAD_PATHS)}")
    ns, name = check_ns(namespace), check_name(name)
    obj = k8s_get(WORKLOAD_PATHS[kind].format(ns=ns, name=name))
    meta, spec, status = obj["metadata"], obj.get("spec", {}), obj.get("status", {})
    ann = meta.get("annotations", {}) or {}
    tmpl = spec.get("jobTemplate", {}).get("spec", {}).get("template") if kind == "CronJob" else spec.get("template")
    out = {
        "kind": kind, "name": name, "age": fmt_age(age_seconds(meta.get("creationTimestamp"))),
        "owner": [f'{o["kind"]}/{o["name"]}' for o in meta.get("ownerReferences", [])],
        "revision": ann.get("deployment.kubernetes.io/revision"),
        "changeCause": ann.get("kubernetes.io/change-cause"),
        "desiredReplicas": spec.get("replicas"),
        "strategy": spec.get("strategy") or spec.get("updateStrategy"),
        "selector": (spec.get("selector") or {}).get("matchLabels"),
        "status": {k: v for k, v in status.items() if k != "conditions"},
        "conditions": [{**{k: c.get(k) for k in ("type", "status", "reason", "message")},
                        "age": fmt_age(age_seconds(c.get("lastTransitionTime") or c.get("lastUpdateTime")))}
                       for c in status.get("conditions", []) or []],
        "containers": [container_spec(c) for c in (tmpl or {}).get("spec", {}).get("containers", [])],
    }
    if kind == "Deployment" and out["selector"]:
        sel = quote(",".join(f"{k}={v}" for k, v in out["selector"].items()))
        rs = k8s_get(f"/apis/apps/v1/namespaces/{ns}/replicasets?labelSelector={sel}")["items"]
        rev = lambda r: int((r["metadata"].get("annotations") or {}).get("deployment.kubernetes.io/revision", 0))
        out["rollouts"] = [{
            "replicaSet": r["metadata"]["name"], "revision": rev(r),
            "age": fmt_age(age_seconds(r["metadata"].get("creationTimestamp"))),
            "images": [c["image"] for c in r["spec"]["template"]["spec"]["containers"]],
            "replicas": r.get("status", {}).get("replicas", 0), "ready": r.get("status", {}).get("readyReplicas", 0),
        } for r in sorted(rs, key=rev, reverse=True)[:4]]
    if kind in ("Deployment", "StatefulSet", "ReplicaSet"):
        summary = f"{status.get('readyReplicas', 0)}/{spec.get('replicas', 0)} ready"
    elif kind == "DaemonSet":
        summary = f"{status.get('numberReady', 0)}/{status.get('desiredNumberScheduled', 0)} ready"
    elif kind == "Job":
        summary = f"{status.get('succeeded', 0)} succeeded, {status.get('failed', 0)} failed"
    else:
        summary = "found"
    return out, summary


def tool_list_pods(namespace, label_selector=""):
    ns = check_ns(namespace)
    if not SELECTOR_RE.match(label_selector or ""):
        raise BadRequest("invalid label selector")
    qs = f"?labelSelector={quote(label_selector)}&limit=50" if label_selector else "?limit=50"
    rows = [pod_row(p) for p in k8s_get(f"/api/v1/namespaces/{ns}/pods{qs}")["items"]]
    compact = [{k: r[k] for k in ("name", "status", "ready", "restarts", "node", "lastReason", "attention")} | {"age": fmt_age(r["age"])} for r in rows]
    bad = sum(1 for r in rows if r["level"] != "ok")
    return {"pods": compact}, f"{len(rows)} pods, {bad} unhealthy"


def tool_get_node(name):
    n = k8s_get(f"/api/v1/nodes/{check_name(name)}")
    status = n.get("status", {})
    snap = STORE.snap or {}
    snap_node = next((x for x in snap.get("nodes", []) if x["name"] == name), {})
    pods = [p for p in snap.get("pods", []) if p["node"] == name]
    conds = [{k: c.get(k) for k in ("type", "status", "reason", "message")} for c in status.get("conditions", [])]
    out = {
        "conditions": conds,
        "unschedulable": n.get("spec", {}).get("unschedulable", False),
        "taints": n.get("spec", {}).get("taints", []),
        "allocatable": status.get("allocatable", {}),
        "usage": {"cpuCores": snap_node.get("cpu"), "memoryBytes": snap_node.get("mem")},
        "nodeInfo": {k: status.get("nodeInfo", {}).get(k) for k in ("kubeletVersion", "osImage", "containerRuntimeVersion")},
        "pods": len(pods),
        "unhealthyPodsOnNode": [f'{p["namespace"]}/{p["name"]}: {p["attention"]}' for p in pods if p["level"] != "ok"][:15],
    }
    bad = [c["type"] for c in conds if (c["type"] == "Ready") != (c["status"] == "True")]
    return out, ("healthy" if not bad else ", ".join(bad))


def tool_get_services(namespace):
    ns = check_ns(namespace)
    svcs = k8s_get(f"/api/v1/namespaces/{ns}/services")["items"]
    eps = {e["metadata"]["name"]: e for e in k8s_get(f"/api/v1/namespaces/{ns}/endpoints")["items"]}
    out = []
    for s in svcs:
        subsets = eps.get(s["metadata"]["name"], {}).get("subsets") or []
        ready = [a for ss in subsets for a in ss.get("addresses", []) or []]
        not_ready = [a for ss in subsets for a in ss.get("notReadyAddresses", []) or []]
        out.append({
            "name": s["metadata"]["name"], "type": s["spec"].get("type"), "selector": s["spec"].get("selector"),
            "ports": [f'{p.get("port")}->{p.get("targetPort")}/{p.get("protocol", "TCP")}' for p in s["spec"].get("ports", [])],
            "readyEndpoints": len(ready), "notReadyEndpoints": len(not_ready),
            "readyPods": [a.get("targetRef", {}).get("name") for a in ready][:6],
        })
    empty = sum(1 for s in out if s["selector"] and not s["readyEndpoints"])
    return {"services": out}, f"{len(out)} services, {empty} with no ready endpoints"


def tool_check_references(namespace, name):
    ns, name = check_ns(namespace), check_name(name)
    spec = k8s_get(f"/api/v1/namespaces/{ns}/pods/{name}").get("spec", {})
    cms, secrets, pvcs = {}, set(), set()
    for c in spec.get("initContainers", []) + spec.get("containers", []):
        for ref in _config_refs(c):
            kind, _, rest = ref.partition(":")
            obj, _, key = rest.partition("/")
            if kind == "configMap":
                cms.setdefault(obj, set()).update([key] if key else [])
            else:
                secrets.add(obj)
    for v in _volumes(spec):
        if v["type"] == "configMap":
            cms.setdefault(v["ref"], set())
        elif v["type"] == "secret":
            secrets.add(v["ref"])
        elif v["type"] == "persistentVolumeClaim":
            pvcs.add(v["ref"])

    def fetch(path):
        try:
            return k8s_get(path)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise

    out, problems = [], 0
    for cm, keys in cms.items():
        obj = fetch(f"/api/v1/namespaces/{ns}/configmaps/{cm}")
        if obj is None:
            problems += 1
            out.append({"configMap": cm, "exists": False})
            continue
        have = set(obj.get("data") or {}) | set(obj.get("binaryData") or {})
        lost = sorted(k for k in keys if k not in have)
        problems += bool(lost)
        out.append({"configMap": cm, "exists": True, "keys": sorted(have)[:40], "missingKeys": lost})
    for claim in pvcs:
        obj = fetch(f"/api/v1/namespaces/{ns}/persistentvolumeclaims/{claim}")
        if obj is None:
            problems += 1
            out.append({"pvc": claim, "exists": False})
            continue
        st = obj.get("status", {})
        problems += st.get("phase") != "Bound"
        out.append({"pvc": claim, "exists": True, "phase": st.get("phase"), "capacity": (st.get("capacity") or {}).get("storage"),
                    "storageClass": obj["spec"].get("storageClassName")})
    for s in sorted(secrets):
        out.append({"secret": s, "checked": False, "note": "KubePulse cannot read Secrets by design"})
    return {"references": out}, f"{len(cms)} ConfigMaps, {len(pvcs)} volumes, {problems} problems"


TOOL_FUNCS = {
    "get_pod": tool_get_pod,
    "get_pod_logs": tool_get_pod_logs,
    "get_events": tool_get_events,
    "get_workload": tool_get_workload,
    "list_pods": tool_list_pods,
    "get_node": tool_get_node,
    "get_services": tool_get_services,
    "check_references": tool_check_references,
}


def _fn(name, description, props, required):
    return {"type": "function", "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": props, "required": required}}}


_S = {"type": "string"}
TOOLS = [
    _fn("get_pod", "Pod status, containers (state, last termination, restarts, resources, probes, config refs), volumes, conditions, current CPU/memory usage and recent events.",
        {"namespace": _S, "name": _S}, ["namespace", "name"]),
    _fn("get_pod_logs", "Tail of a container's logs. Use previous=true to read the run that crashed.",
        {"namespace": _S, "name": _S, "container": _S, "previous": {"type": "boolean"}, "tail_lines": {"type": "integer"}},
        ["namespace", "name", "container"]),
    _fn("get_events", "Events for one object (give name) or the namespace's recent Warning events (omit name).",
        {"namespace": _S, "name": _S}, ["namespace"]),
    _fn("get_workload", "Owning workload: replicas, conditions, strategy, pod template containers. For a Deployment also its recent rollouts (revisions and images).",
        {"namespace": _S, "kind": {"type": "string", "enum": list(WORKLOAD_PATHS)}, "name": _S}, ["namespace", "kind", "name"]),
    _fn("list_pods", "Pods in a namespace, optionally filtered by label selector (e.g. app=payments). Use to see whether sibling replicas fail the same way.",
        {"namespace": _S, "label_selector": _S}, ["namespace"]),
    _fn("get_node", "A node's conditions (memory/disk pressure), taints, allocatable, usage and unhealthy pods on it.",
        {"name": _S}, ["name"]),
    _fn("get_services", "Services in a namespace with their ready and not-ready endpoint counts. Use for connection refused / timeout errors to dependencies.",
        {"namespace": _S}, ["namespace"]),
    _fn("check_references", "Whether the ConfigMaps (and keys) and PersistentVolumeClaims a pod uses exist and are bound.",
        {"namespace": _S, "name": _S}, ["namespace", "name"]),
]


def step_label(name, a):
    target = a.get("name", "")
    return {
        "get_pod": f"Inspected pod {target}",
        "get_pod_logs": f"Read {'crashed-run ' if a.get('previous') else ''}logs of {a.get('container', '')} in {target}",
        "get_events": f"Read events for {target}" if target else f"Read warning events in {a.get('namespace', '')}",
        "get_workload": f"Checked {a.get('kind', 'workload')} {target}",
        "list_pods": f"Compared pods {('matching ' + a['label_selector']) if a.get('label_selector') else 'in ' + a.get('namespace', '')}",
        "get_node": f"Checked node {target}",
        "get_services": f"Checked services and endpoints in {a.get('namespace', '')}",
        "check_references": f"Checked ConfigMaps and volumes used by {target}",
    }.get(name, name)


AI_PROMPT = """You are KubePulse's on-call Kubernetes investigator. A pod is unhealthy. Find the real
root cause yourself with the read-only tools, the way a senior SRE would:
- Start from the evidence you're given, then dig: read logs (previous=true for crashed containers),
  look at the owning workload and its recent rollouts, compare sibling pods, check the node, check
  services/endpoints the app talks to, and check that referenced ConfigMaps and volumes exist.
- Follow the evidence. Don't call tools you don't need. Stop as soon as you're confident.
- Never ask the user to run commands or check things: you are the one investigating. If something
  can't be checked with your tools (Secret contents, external databases, cloud resources), say so.

Final report in Markdown for the developer on call:
## Verdict
One sentence: what is broken and why.
## Root cause
The cause, your confidence (High / Medium / Low) and why.
## What I found
Bullets of concrete findings from your investigation: quote log lines, events and numbers.
## Impact
What is affected (e.g. 2 of 3 replicas down, service has no ready endpoints), or "Limited to this pod".
## Fix
The specific change to make (which resource, which field, what value) in plain words. No kubectl
commands, unless the fix is a one-off action like a rollback; then at most one.
Keep the report under 300 words."""

JOBS = {}
JOBS_LOCK = threading.Lock()


def openai_chat(messages, **extra):
    return post_json(
        OPENAI_BASE_URL + "/chat/completions",
        {"model": OPENAI_MODEL, "temperature": 0.1, "messages": messages, **extra},
        headers={"Authorization": "Bearer " + OPENAI_API_KEY},
        timeout=120,
    )


def start_investigation(ns, name, fresh=False):
    if not OPENAI_API_KEY:
        raise BadRequest("AI investigation is off. Set OPENAI_API_KEY in the kubepulse-secrets Secret.")
    with JOBS_LOCK:
        now = time.time()
        for jid in [j for j, job in JOBS.items() if now - job["created"] > 1800]:
            del JOBS[jid]
        if not fresh:
            recent = [j for j in JOBS.values() if (j["ns"], j["name"]) == (ns, name) and j["status"] != "error" and now - j["created"] < 600]
            if recent:
                return max(recent, key=lambda j: j["created"])["id"]
        if sum(1 for j in JOBS.values() if j["status"] == "running") >= 3:
            raise BadRequest("Three investigations are already running. Try again in a minute.")
        job = {"id": uuid.uuid4().hex[:12], "ns": ns, "name": name, "status": "running", "steps": [],
               "answer": None, "error": None, "model": OPENAI_MODEL, "created": now, "finished": None}
        JOBS[job["id"]] = job
    threading.Thread(target=investigate, args=(job,), daemon=True).start()
    return job["id"]


def investigate(job):
    ns, name = job["ns"], job["name"]
    try:
        first, summary = tool_get_pod(ns, name)
        job["steps"].append({"label": f"Inspected pod {name}", "result": summary, "status": "done"})
        messages = [
            {"role": "system", "content": AI_PROMPT},
            {"role": "user", "content": f"Investigate pod {ns}/{name}. Current state:\n" + redact(json.dumps(first, indent=1))[:14000]},
        ]
        for _ in range(AI_MAX_STEPS):
            out = openai_chat(messages, tools=TOOLS, tool_choice="auto")
            job["model"] = out.get("model", OPENAI_MODEL)
            msg = out["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                job["answer"] = msg.get("content") or ""
                break
            messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": calls})
            for call in calls:
                fname = call["function"]["name"]
                try:
                    args = json.loads(call["function"].get("arguments") or "{}")
                except ValueError:
                    args = {}
                step = {"label": step_label(fname, args), "result": "", "status": "running"}
                job["steps"].append(step)
                try:
                    if fname not in TOOL_FUNCS:
                        raise BadRequest(f"unknown tool {fname}")
                    result, step["result"] = TOOL_FUNCS[fname](**args)
                    step["status"] = "done"
                    content = redact(json.dumps(result, indent=1))[:9000]
                except Exception as e:
                    step["status"], step["result"] = "error", api_error(e)[1][:160]
                    content = "Error: " + step["result"]
                messages.append({"role": "tool", "tool_call_id": call["id"], "content": content})
        else:
            messages.append({"role": "user", "content": "Stop investigating now and write the final report."})
            job["answer"] = openai_chat(messages, tools=TOOLS, tool_choice="none")["choices"][0]["message"].get("content") or ""
        job["status"] = "done"
    except Exception as e:
        job["status"], job["error"] = "error", api_error(e)[1]
    job["finished"] = time.time()


def job_view(job):
    return {k: job[k] for k in ("id", "status", "steps", "answer", "error", "model")} | {
        "at": datetime.fromtimestamp(job["finished"] or job["created"], timezone.utc).isoformat(),
        "seconds": round((job["finished"] or time.time()) - job["created"]),
    }


# ---------- Mattermost alerts ----------

class Alerter:
    """Posts new problems and recoveries to Mattermost, once each, with flap protection."""

    def __init__(self):
        self.active = {}     # key -> alert dict (+ since, notified)
        self.cooldown = {}   # key -> when it last resolved or last alerted (one-off alerts)
        self.restarts = {}   # (ns, name) -> restarts seen last poll
        self.started = False
        self.last_sent = self.last_error = None
        self.last_test = 0.0

    def status(self):
        return {"enabled": bool(MATTERMOST_WEBHOOK_URL), "lastSent": self.last_sent, "lastError": self.last_error,
                "active": len(self.active), "pendingMinutes": ALERT_PENDING // 60, "cooldownMinutes": ALERT_COOLDOWN // 60}

    def _current(self, snap):
        latest = {}
        for e in reversed(snap.get("warnings") or []):   # oldest first, so the newest message wins
            if e["kind"] == "Pod":
                latest[(e["namespace"], e["name"])] = e["message"]
        cur, oom = {}, []
        for n in snap["nodes"]:
            if not n["ready"]:
                cur[("node", n["name"])] = {"kind": "node", "title": f"Node {n['name']}", "reason": "NotReady",
                                            "level": "bad", "detail": ", ".join(n["pressure"]), "fields": {}}
        seen = set()
        for p in snap["pods"]:
            pk = (p["namespace"], p["name"])
            seen.add(pk)
            prev = self.restarts.get(pk)
            self.restarts[pk] = p["restarts"]
            stuck = p["kind"] in ("pending", "notready") and (p["stateAge"] or 0) >= ALERT_PENDING
            alert = {"kind": "pod", "ns": p["namespace"], "name": p["name"], "title": f"{p['namespace']}/{p['name']}",
                     "detail": latest.get(pk, ""), "fields": {"Node": p["node"] or "not scheduled", "Restarts": str(p["restarts"])}}
            if p["kind"] in ("failing", "finished") or stuck:
                reason = p["attention"] + (f" for {fmt_age(p['stateAge'])}" if stuck else "")
                cur[("pod",) + pk] = dict(alert, reason=reason, level="bad" if p["kind"] == "failing" else "warn")
            elif p["lastReason"] == "OOMKilled" and prev is not None and p["restarts"] > prev:
                oom.append(dict(alert, reason="OOMKilled and restarted", level="warn"))
        for pk in set(self.restarts) - seen:
            del self.restarts[pk]
        for c in snap.get("certs") or []:
            if c["daysLeft"] is not None and c["daysLeft"] < CERT_WARN_DAYS:
                expired = c["daysLeft"] <= 0
                cur[("cert", c["namespace"], c["name"])] = {
                    "kind": "cert", "title": f"Certificate {c['namespace']}/{c['name']}", "level": "bad" if c["daysLeft"] < 3 else "warn",
                    "reason": "Expired" if expired else f"Expires in {c['daysLeft']:.0f} days",
                    "detail": ", ".join(c["dnsNames"]), "fields": {"Secret": c["secret"] or "-"}}
        for v in snap.get("pvcs") or []:
            if v["percent"] is not None and v["percent"] >= PVC_WARN_PERCENT:
                cur[("pvc", v["namespace"], v["name"])] = {
                    "kind": "pvc", "title": f"Volume {v['namespace']}/{v['name']}", "level": "bad" if v["percent"] >= 95 else "warn",
                    "reason": f"{v['percent']:.0f}% full", "detail": f"Used by {v['pod']}" if v["pod"] else "",
                    "fields": {"Size": v["size"] or "-"}}
        return cur, oom

    def check(self, snap):
        if not MATTERMOST_WEBHOOK_URL:
            return
        now = time.time()
        cur, oom = self._current(snap)
        if not self.started:
            # Don't replay every existing problem on each restart: one summary instead
            self.started = True
            self.active = {k: dict(v, since=now, notified=True) for k, v in cur.items()}
            if cur:
                self.send(f"#### :information_source: {self._prefix()}KubePulse is watching the cluster. "
                          f"{len(cur)} problem{'s' if len(cur) != 1 else ''} right now:", list(cur.values()))
            return
        new = []
        for k, v in cur.items():
            if k in self.active:
                self.active[k].update(reason=v["reason"], detail=v["detail"])
                continue
            notify = now - self.cooldown.get(k, 0) > ALERT_COOLDOWN
            self.active[k] = dict(v, since=now, notified=notify)
            if notify:
                new.append(v)
        for a in oom:
            k = ("oom", a["ns"], a["name"])
            if now - self.cooldown.get(k, 0) > ALERT_COOLDOWN:
                self.cooldown[k] = now
                new.append(a)
        resolved = [(k, self.active.pop(k)) for k in list(self.active) if k not in cur]
        for k, _ in resolved:
            self.cooldown[k] = now
        self.cooldown = {k: t for k, t in self.cooldown.items() if now - t < ALERT_COOLDOWN}

        if new:
            n = len(new)
            self.send(f"#### :rotating_light: {self._prefix()}{n} new problem{'s' if n != 1 else ''}", new)
        done = [v for _, v in resolved if v["notified"]]
        if done and ALERT_RESOLVED:
            lines = [f"**{v['title']}** was {v['reason'].split(' for ')[0]}, lasted {fmt_age(int(now - v['since']))}" for v in done[:15]]
            more = f"\n…and {len(done) - 15} more" if len(done) > 15 else ""
            self.send(f":white_check_mark: {self._prefix()}Resolved\n" + "\n".join("- " + line for line in lines) + more)

    def _prefix(self):
        return f"[{CLUSTER_NAME}] " if CLUSTER_NAME else ""

    def _attachment(self, a):
        att = {
            "color": "#e5484d" if a["level"] == "bad" else "#e08a00",
            "fallback": f"{a['title']}: {a['reason']}",
            "title": a["title"],
            "text": f"**{a['reason']}**" + (f"\n{a['detail']}" if a["detail"] else ""),
            "fields": [{"short": True, "title": k, "value": v} for k, v in a["fields"].items()],
        }
        if DASHBOARD_URL and a["kind"] == "pod":
            att["title_link"] = f"{DASHBOARD_URL}/#pod/{a['ns']}/{a['name']}"
        return att

    def send(self, text, alerts=()):
        alerts = list(alerts)
        if len(alerts) > 10:
            text += f"\nShowing 10 of {len(alerts)}. Open KubePulse for the full list."
        body = {"username": "KubePulse", "text": text, "attachments": [self._attachment(a) for a in alerts[:10]]}
        try:
            post_json(MATTERMOST_WEBHOOK_URL, body)
            self.last_sent, self.last_error = now_iso(), None
        except Exception as e:
            self.last_error = api_error(e)[1]
            print(f"mattermost alert failed: {self.last_error}", flush=True)

    def test(self):
        if not MATTERMOST_WEBHOOK_URL:
            raise BadRequest("Alerts are off. Set MATTERMOST_WEBHOOK_URL in the kubepulse-secrets Secret.")
        if time.time() - self.last_test < 60:
            raise BadRequest("A test message was sent less than a minute ago.")
        self.last_test = time.time()
        self.send(f":white_check_mark: {self._prefix()}Test message from KubePulse. Alerts reach this channel.")
        if self.last_error:
            raise BadRequest(f"Mattermost rejected the message: {self.last_error}")
        return json.dumps({"ok": True, "sentAt": self.last_sent})


ALERTS = Alerter()


# ---------- Background poller and snapshot store ----------

class Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.snap = self.body = self.gz = self.etag = self.error = None

    def publish(self, snap):
        body = json.dumps(snap, separators=(",", ":")).encode()
        gz = gzip.compress(body, 6)
        with self.lock:
            self.snap, self.body, self.gz = snap, body, gz
            self.etag = '"' + hashlib.sha1(body).hexdigest()[:20] + '"'


STORE = Store()


def poll_loop():
    while True:
        started = time.time()
        try:
            snap = build_snapshot()
            record_history(snap)
            INSIGHTS.update(snap)
            ALERTS.check(snap)
            snap["alerts"] = ALERTS.status()
            STORE.publish(snap)
        except Exception as e:
            msg = api_error(e)[1]
            print(f"poll failed: {msg}", flush=True)
            if STORE.snap:
                STORE.publish(dict(STORE.snap, error=msg))
            else:
                STORE.error = msg
        time.sleep(max(1.0, POLL_SECONDS - (time.time() - started)))


# ---------- HTTP ----------

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in {"Cache-Control": "no-store", **(headers or {})}.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _gzip_ok(self):
        return "gzip" in (self.headers.get("Accept-Encoding") or "")

    def _api(self, fn, ctype="application/json"):
        try:
            body = fn()
            self._send(200, body if isinstance(body, bytes) else body.encode(), ctype)
        except Exception as e:
            code, msg = api_error(e)
            self._send(code, json.dumps({"error": msg}).encode(), "application/json")

    def _snapshot(self):
        with STORE.lock:
            body, gz, etag = STORE.body, STORE.gz, STORE.etag
        if body is None:
            msg = STORE.error or "KubePulse is starting up"
            return self._send(503, json.dumps({"error": msg}).encode(), "application/json")
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.end_headers()
            return
        headers = {"ETag": etag, "Cache-Control": "no-cache", "Vary": "Accept-Encoding"}
        if self._gzip_ok():
            headers["Content-Encoding"] = "gzip"
            return self._send(200, gz, "application/json", headers)
        self._send(200, body, "application/json", headers)

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path in ("/", "/index.html"):
            if self._gzip_ok():
                self._send(200, INDEX_GZ, "text/html; charset=utf-8", {"Content-Encoding": "gzip", "Vary": "Accept-Encoding"})
            else:
                self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        elif url.path == "/api/snapshot":
            self._snapshot()
        elif url.path == "/api/pod":
            self._api(lambda: json.dumps(pod_detail(check_ns(q.get("ns")), check_name(q.get("name")))))
        elif url.path == "/api/logs":
            self._api(lambda: pod_logs(check_ns(q.get("ns")), check_name(q.get("name")),
                                       check_name(q.get("container"), "container"), q.get("previous") == "1"),
                      "text/plain; charset=utf-8")
        elif url.path == "/api/investigation":
            def view():
                job = JOBS.get(q.get("id", ""))
                if not job:
                    raise BadRequest("investigation not found; it may have expired")
                return json.dumps(job_view(job))
            self._api(view)
        elif url.path == "/healthz":
            self._send(200, b"ok", "text/plain")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/api/investigate":
            self._api(lambda: json.dumps({"id": start_investigation(check_ns(q.get("ns")), check_name(q.get("name")),
                                                                   fresh=q.get("fresh") == "1")}))
        elif url.path == "/api/alerts/test":
            self._api(ALERTS.test)
        else:
            self._send(404, b"not found", "text/plain")

    def log_message(self, fmt, *args):
        if not self.path.startswith(("/healthz", "/api/snapshot", "/api/investigation")):
            super().log_message(fmt, *args)


if __name__ == "__main__":
    print(f"KubePulse listening on :{PORT} (API: {BASE_URL}, poll every {POLL_SECONDS}s, "
          f"AI {'on' if OPENAI_API_KEY else 'off'}, alerts {'on' if MATTERMOST_WEBHOOK_URL else 'off'})", flush=True)
    threading.Thread(target=poll_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    server.serve_forever()
