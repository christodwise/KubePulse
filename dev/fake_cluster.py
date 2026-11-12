"""A fake cluster for developing KubePulse without a real one.

Serves a small Kubernetes API (with failing pods, events, logs, workloads, services, volumes,
certificates, a Prometheus and a PostgreSQL primary and replica with their exporters), a scripted
OpenAI-compatible model and a Mattermost webhook that prints what it receives.

    python3 dev/fake_cluster.py
    K8S_API=http://127.0.0.1:8911 DATA_DIR=/tmp OPENAI_API_KEY=x OPENAI_BASE_URL=http://127.0.0.1:8912/v1 \\
      MATTERMOST_WEBHOOK_URL=http://127.0.0.1:8913/hook PG_URLS=prod/postgres=postgresql://kubepulse:demo@127.0.0.1:8914/postgres \\
      python3 app.py
"""
import json
import os
import random
import socketserver
import struct
import threading
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

random.seed(7)
NOW = datetime.now(timezone.utc)
ts = lambda sec: (NOW - timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
future = lambda sec: (NOW + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
HOOK_LOG = os.getenv("HOOK_LOG", "")
STARTED = time.time()
ROLL_AFTER = float(os.getenv("ROLL_AFTER", "40"))   # seconds until payments-api rolls out a new version

NODES = [("node-system-0", "m5.xlarge", "4", "16Gi", "3860m", "14Gi"),
         ("node-apps-1", "m5.2xlarge", "8", "32Gi", "7910m", "29Gi"),
         ("node-apps-2", "m5.2xlarge", "8", "32Gi", "7910m", "29Gi")]
NODE_NAMES = [n[0] for n in NODES]
PODS, EVENTS = [], []


def pod(ns, name, node, app, state=None, last=None, restarts=0, ready=True, image="nginx:1.27", owner=None,
        req=("100m", "128Mi"), limit="256Mi", age=None, configmap=None, claim=None):
    tmpl_hash = "7d9f8c6b5"
    status = {"name": "app", "ready": ready, "restartCount": restarts, "image": image,
              "state": state or {"running": {"startedAt": ts(3600)}}}
    if last:
        status["lastState"] = {"terminated": last}
    container = {"name": "app", "image": image, "resources": {"requests": {"cpu": req[0], "memory": req[1]},
                 "limits": {"memory": limit, **({"cpu": "2" if req[0] == "1500m" else "300m"} if hash(name) % 4 else {})}},
                 "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}, "periodSeconds": 10}}
    if configmap:
        container["envFrom"] = [{"configMapRef": {"name": configmap}}]
    p = {"metadata": {"namespace": ns, "name": name, "creationTimestamp": ts(age or random.randint(7200, 900000)),
                      "labels": {"app": app, "pod-template-hash": tmpl_hash},
                      "ownerReferences": [{"kind": owner[0], "name": owner[1]} if owner else {"kind": "ReplicaSet", "name": f"{app}-{tmpl_hash}"}]},
         "spec": {"nodeName": node, "containers": [container],
                  "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": claim}}] if claim else []},
         "status": {"phase": "Running", "podIP": f"10.244.{random.randint(0, 3)}.{random.randint(2, 250)}", "qosClass": "Burstable",
                    "containerStatuses": [status],
                    "conditions": [{"type": "Ready", "status": "True" if ready else "False", "lastTransitionTime": ts(7200 if ready else 600)}]}}
    if not node:
        del p["spec"]["nodeName"]
        p["status"] = {"phase": "Pending", "qosClass": "Burstable", "conditions": [{"type": "Ready", "status": "False", "lastTransitionTime": ts(400)}]}
    PODS.append(p)
    return p


def event(ns, name, reason, message, kind="Warning", age=60, count=1):
    EVENTS.append({"metadata": {"namespace": ns, "name": f"{name}.{random.randint(1, 10**9):x}", "creationTimestamp": ts(age)},
                   "involvedObject": {"kind": "Pod", "namespace": ns, "name": name}, "type": kind, "reason": reason,
                   "message": message, "count": count, "lastTimestamp": ts(age)})


APPS = ["checkout", "catalog", "search", "notifications", "reports", "auth", "gateway", "billing", "grafana", "prometheus", "coredns", "metrics-agent"]
for i in range(int(os.getenv("PODS", "54"))):
    app = APPS[i % len(APPS)]
    ns = "monitoring" if app in ("grafana", "prometheus") else "kube-system" if app in ("coredns", "metrics-agent") else random.choice(["prod", "uat"])
    big = app in ("reports", "search")
    pod(ns, f"{app}-7d9f8c6b5-{random.randint(10000, 99999):x}", random.choice(NODE_NAMES), app,
        req=("1500m", "2Gi") if big else ("100m", "128Mi"), limit="3Gi" if big else "256Mi", age=1500 if app == "gateway" and i % 2 else None)

OOM = {"reason": "OOMKilled", "exitCode": 137, "finishedAt": ts(90), "startedAt": ts(160)}
for j, suffix in enumerate(["x2k4p", "m8q1z", "t5w7r"]):
    pod("prod", f"payments-api-7d9f8c6b5-{suffix}", NODE_NAMES[2 - j % 2], "payments-api",
        state={"waiting": {"reason": "CrashLoopBackOff", "message": "back-off 5m0s restarting failed container"}} if j < 2 else None,
        last=OOM, restarts=[23, 19, 4][j], ready=j == 2, image="example/payments:2.4.1", age=5400, configmap="payments-config")
event("prod", "payments-api-7d9f8c6b5-x2k4p", "BackOff", "Back-off restarting failed container app in pod payments-api-7d9f8c6b5-x2k4p", age=30, count=87)
event("prod", "payments-api-7d9f8c6b5-x2k4p", "Killing", "Container app exceeded its memory limit and was OOMKilled", age=95, count=23)
pod("uat", "web-frontend-5c6b8d7f9-q2n4m", NODE_NAMES[1], "web-frontend", ready=False, image="example/web:3.0.0-rc", age=1200,
    state={"waiting": {"reason": "ImagePullBackOff", "message": 'Back-off pulling image "example/web:3.0.0-rc"'}})
event("uat", "web-frontend-5c6b8d7f9-q2n4m", "Failed", 'Failed to pull image "example/web:3.0.0-rc": manifest unknown', age=40, count=12)
pod("prod", "report-worker-6b7c9d-x1", "", "report-worker", ready=False, age=400)
event("prod", "report-worker-6b7c9d-x1", "FailedScheduling", "0/3 nodes are available: 3 Insufficient memory.", age=20, count=9)
pod("prod", "postgres-0", NODE_NAMES[1], "postgres", owner=("StatefulSet", "postgres"), req=("500m", "1Gi"), limit="2Gi", claim="pg-data")
pod("uat", "orders-api-9f2c1b8d4-a1", NODE_NAMES[1], "orders-api", last={"reason": "Error", "exitCode": 1, "finishedAt": ts(1200)}, restarts=2)

LOGS = """2026-09-24T06:28:01Z INFO  Starting payments-api v2.4.1
2026-09-24T06:28:02Z INFO  Connecting to postgres://payments@postgres:5432/payments
2026-09-24T06:28:03Z INFO  Warming settlement cache (batch=50000)
2026-09-24T06:28:40Z WARN  Heap usage 210Mi / 256Mi
2026-09-24T06:28:55Z WARN  Heap usage 249Mi / 256Mi, GC overhead 71%
2026-09-24T06:29:01Z ERROR java.lang.OutOfMemoryError: Java heap space
\tat com.example.payments.cache.SettlementCache.load(SettlementCache.java:88)
"""
VOLUMES = {("prod", "pg-data"): (46, 50), ("monitoring", "prometheus-db"): (61, 100)}   # GiB used, GiB size


def workloads(kind):
    """Deployments / StatefulSets derived from the fake pods; payments-api gets a new image after ROLL_AFTER seconds."""
    if kind == "daemonsets":
        return []
    out, seen = [], set()
    for p in PODS:
        ref = p["metadata"]["ownerReferences"][0]
        is_sts = ref["kind"] == "StatefulSet"
        if (kind == "statefulsets") != is_sts or ref["kind"] not in ("ReplicaSet", "StatefulSet"):
            continue
        ns, app = p["metadata"]["namespace"], p["metadata"]["labels"]["app"]
        name = ref["name"] if is_sts else app
        if (ns, name) in seen:
            continue
        seen.add((ns, name))
        image = p["spec"]["containers"][0]["image"]
        rolled = name == "payments-api" and time.time() - STARTED > ROLL_AFTER
        if name == "payments-api":
            image = "example/payments:2.4.1" if rolled else "example/payments:2.4.0"
        replicas = sum(1 for x in PODS if x["metadata"]["namespace"] == ns and x["metadata"]["labels"]["app"] == app)
        out.append({"metadata": {"namespace": ns, "name": name, "generation": 2 if rolled else 1,
                                 "annotations": {"deployment.kubernetes.io/revision": "14" if rolled else "13"}},
                    "spec": {"replicas": replicas, "template": {"metadata": {"labels": {"app": app}},
                             "spec": {"containers": [dict(p["spec"]["containers"][0], image=image)]}}},
                    "status": {"observedGeneration": 2 if rolled else 1, "replicas": replicas, "updatedReplicas": replicas,
                               "readyReplicas": 1 if name == "payments-api" else replicas}})
    return out


def find(ns, name):
    return next((p for p in PODS if p["metadata"]["namespace"] == ns and p["metadata"]["name"] == name), None)


class Kubernetes(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send(self, body, code=200, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        url = urlparse(self.path)
        path, q = url.path, parse_qs(url.query)
        parts = path.strip("/").split("/")
        field = q.get("fieldSelector", [""])[0]
        if path == "/api/v1/pods":
            return self.send({"items": PODS})
        if path == "/api/v1/nodes":
            return self.send({"items": [{
                "metadata": {"name": n, "creationTimestamp": ts(86400 * 12), "labels": {
                    "node-role.kubernetes.io/" + ("system" if i == 0 else "apps"): "", "node.kubernetes.io/instance-type": kind,
                    "topology.kubernetes.io/zone": "us-east-1" + "abc"[i]}},
                "spec": {"providerID": f"aws:///us-east-1a/i-0{i}"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}, {"type": "MemoryPressure", "status": "True" if i == 2 else "False"}],
                           "nodeInfo": {"kubeletVersion": "v1.30.4"}, "capacity": {"cpu": cpu, "memory": mem},
                           "allocatable": {"cpu": acpu, "memory": amem, "pods": "110"}}}
                for i, (n, kind, cpu, mem, acpu, amem) in enumerate(NODES)]})
        if path.startswith("/api/v1/nodes/"):
            return self.send({"metadata": {"name": parts[3]}, "spec": {}, "status": {
                "conditions": [{"type": "Ready", "status": "True"}, {"type": "MemoryPressure", "status": "True" if parts[3] == NODE_NAMES[2] else "False",
                                                                      "message": "kubelet has insufficient memory available"}],
                "allocatable": {"cpu": "7910m", "memory": "29Gi"}, "nodeInfo": {"kubeletVersion": "v1.30.4"}}})
        if path == "/apis/metrics.k8s.io/v1beta1/nodes":
            return self.send({"items": [{"metadata": {"name": n}, "usage": {"cpu": f"{random.randint(900, 3200)}m", "memory": f"{random.randint(5, 11)}Gi"}} for n in NODE_NAMES]})
        if path == "/apis/metrics.k8s.io/v1beta1/pods":
            return self.send({"items": [{
                "metadata": {"namespace": p["metadata"]["namespace"], "name": p["metadata"]["name"]},
                "containers": [{"usage": {"cpu": f"{random.randint(20, 90) if p['metadata']['labels']['app'] in ('reports', 'search') else random.randint(1, 300)}m",
                                          "memory": f"{random.randint(20, 200)}Mi"}}]}
                for p in PODS if p["spec"].get("nodeName")]})
        if path in ("/apis/apps/v1/deployments", "/apis/apps/v1/statefulsets", "/apis/apps/v1/daemonsets"):
            return self.send({"items": workloads(path.rsplit("/", 1)[1])})
        if path == "/api/v1/events":
            return self.send({"items": [e for e in EVENTS if e["type"] == "Warning"]})
        if path == "/api/v1/services":
            return self.send({"items": [{"metadata": {"name": n, "namespace": ns}, "spec": {"type": "ClusterIP", "ports": [{"port": port, "name": "web"}]}}
                                        for ns, n, port in (("prod", "api", 80), ("monitoring", "prometheus-operated", 9090),
                                                            ("monitoring", "prometheus-prometheus-node-exporter", 9100),
                                                            ("prod", "postgres-metrics", 9187), ("prod", "postgres-read-metrics", 9187))]})
        if path in ("/api/v1/namespaces/prod/services/postgres-metrics:9187/proxy/metrics",
                    "/api/v1/namespaces/prod/services/postgres-read-metrics:9187/proxy/metrics"):
            return self.send(exporter_metrics(replica="read" in path), ctype="text/plain")
        if path.startswith("/api/v1/namespaces/monitoring/services/prometheus-operated:9090/proxy/api/v1/query"):
            used = "used" in q.get("query", [""])[0]
            return self.send({"status": "success", "data": {"resultType": "vector", "result": [
                {"metric": {"namespace": ns, "persistentvolumeclaim": n}, "value": [0, str((u if used else size) * 2**30)]}
                for (ns, n), (u, size) in VOLUMES.items()]}})
        if path == "/api/v1/persistentvolumeclaims":
            return self.send({"items": [{"metadata": {"namespace": ns, "name": n}, "spec": {"storageClassName": "gp3"},
                                         "status": {"phase": "Bound", "capacity": {"storage": f"{size}Gi"}}}
                                        for (ns, n), (_, size) in VOLUMES.items()]})
        if path == "/apis/cert-manager.io/v1/certificates":
            return self.send({"items": [{"metadata": {"namespace": "prod", "name": n}, "spec": {"secretName": n + "-tls", "dnsNames": d},
                                         "status": {"notAfter": future(days * 86400), "conditions": [{"type": "Ready", "status": "True"}]}}
                                        for n, d, days in (("api-gateway", ["api.example.com"], 5.4), ("web-portal", ["portal.example.com"], 42),
                                                           ("grafana", ["grafana.example.com"], 18))]})
        if path == "/apis/apps/v1/namespaces/prod/deployments/payments-api":
            return self.send({"metadata": {"name": "payments-api", "creationTimestamp": ts(86400 * 40), "annotations": {"deployment.kubernetes.io/revision": "14"}},
                              "spec": {"replicas": 3, "selector": {"matchLabels": {"app": "payments-api"}},
                                       "template": {"spec": {"containers": [find("prod", "payments-api-7d9f8c6b5-x2k4p")["spec"]["containers"][0]]}}},
                              "status": {"replicas": 3, "readyReplicas": 1, "availableReplicas": 1,
                                         "conditions": [{"type": "Available", "status": "False", "reason": "MinimumReplicasUnavailable", "lastTransitionTime": ts(5000)}]}})
        if path == "/apis/apps/v1/namespaces/prod/replicasets":
            return self.send({"items": [
                {"metadata": {"name": "payments-api-7d9f8c6b5", "creationTimestamp": ts(5400), "annotations": {"deployment.kubernetes.io/revision": "14"}},
                 "spec": {"template": {"spec": {"containers": [{"image": "example/payments:2.4.1"}]}}}, "status": {"replicas": 3, "readyReplicas": 1}},
                {"metadata": {"name": "payments-api-5b8c7d6f4", "creationTimestamp": ts(86400 * 6), "annotations": {"deployment.kubernetes.io/revision": "13"}},
                 "spec": {"template": {"spec": {"containers": [{"image": "example/payments:2.3.9"}]}}}, "status": {"replicas": 0}}]})
        if len(parts) == 5 and parts[2] == "namespaces" and parts[4] == "pods":
            selector = q.get("labelSelector", [""])[0]
            return self.send({"items": [p for p in PODS if p["metadata"]["namespace"] == parts[3]
                                        and (not selector or selector == "app=" + p["metadata"]["labels"]["app"])]})
        if len(parts) == 6 and parts[4] == "pods":
            p = find(parts[3], parts[5])
            return self.send(p) if p else self.send({"message": f'pods "{parts[5]}" not found'}, 404)
        if len(parts) == 5 and parts[4] == "events":
            name = field.split("involvedObject.name=")[1].split(",")[0] if "involvedObject.name=" in field else None
            return self.send({"items": [e for e in EVENTS if e["metadata"]["namespace"] == parts[3] and (not name or e["involvedObject"]["name"] == name)]})
        if len(parts) == 6 and parts[4] == "configmaps":
            if parts[5] == "payments-config":
                return self.send({"data": {"DB_HOST": "postgres", "CACHE_BATCH": "50000"}})
            return self.send({"message": "not found"}, 404)
        if len(parts) == 7 and parts[6] == "log":
            name = parts[5]
            if "web-frontend" in name:
                return self.send({"message": f'container "app" in pod "{name}" is waiting to start: trying and failing to pull image'}, 400)
            if name.startswith("payments-api") and "previous" not in q and "t5w7r" not in name:
                return self.send({"message": f'container "app" in pod "{name}" is waiting to start: CrashLoopBackOff'}, 400)
            return self.send(LOGS if name.startswith("payments-api") else "INFO started\nINFO GET /healthz 200\n", ctype="text/plain")
        self.send({"message": "not found " + path}, 404)


class Model(BaseHTTPRequestHandler):
    """A scripted OpenAI-compatible model: calls a few tools, then writes a report."""
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        tool_messages = sum(1 for m in body["messages"] if m["role"] == "tool")
        if "tools" not in body:   # the short analysis sent with a CrashLoopBackOff alert
            reply = ("**Cause:** The container runs out of Java heap while warming its settlement cache and is OOMKilled.\n"
                     "**Evidence:** `java.lang.OutOfMemoryError: Java heap space` after heap reached 249Mi / 256Mi.\n"
                     "**Fix:** Raise the memory limit of container `app` in Deployment `payments-api` from 256Mi to 768Mi.")
            data = json.dumps({"model": "fake-model", "choices": [{"message": {"role": "assistant", "content": reply}}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data))); self.end_headers()
            return self.wfile.write(data)
        call = lambda i, name, args: {"id": f"call_{i}", "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}
        pod_name = "payments-api-7d9f8c6b5-x2k4p"
        if tool_messages == 0:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                call(1, "get_pod_logs", {"namespace": "prod", "name": pod_name, "container": "app", "previous": True}),
                call(2, "get_workload", {"namespace": "prod", "kind": "Deployment", "name": "payments-api"})]}
        elif tool_messages == 2:
            msg = {"role": "assistant", "content": None, "tool_calls": [
                call(3, "list_pods", {"namespace": "prod", "label_selector": "app=payments-api"}),
                call(4, "get_node", {"name": NODE_NAMES[2]}), call(5, "check_references", {"namespace": "prod", "name": pod_name})]}
        else:
            msg = {"role": "assistant", "content": (
                "## Verdict\npayments-api runs out of Java heap while warming its settlement cache, so 2 of 3 replicas crash-loop.\n\n"
                "## Root cause\nThe 256Mi memory limit is too small for revision 14, which loads the cache in batches of 50,000. Confidence: **High**.\n\n"
                "## What I found\n- Crashed-run logs end with `java.lang.OutOfMemoryError: Java heap space` after heap reached 249Mi / 256Mi.\n"
                "- Revision 14 (`example/payments:2.4.1`) rolled out 90 minutes ago; revision 13 ran for 6 days without restarts.\n"
                "- 2 of 3 replicas are in CrashLoopBackOff (23 and 19 restarts).\n- ConfigMap `payments-config` sets `CACHE_BATCH=50000`.\n\n"
                "## Impact\nDeployment payments-api has 1 of 3 replicas available.\n\n"
                "## Fix\n1. Raise the memory limit of container `app` in Deployment `payments-api` from 256Mi to 768Mi.\n"
                "2. Or lower `CACHE_BATCH` in ConfigMap `payments-config` to 10000.")}
        data = json.dumps({"model": "fake-model", "choices": [{"message": msg}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class Webhook(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        print("mattermost:", body["text"].replace("\n", " / "), flush=True)
        if HOOK_LOG:
            with open(HOOK_LOG, "a") as f:
                f.write(json.dumps(body) + "\n")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


# ---------- PostgreSQL: a postgres_exporter and a tiny server that answers KubePulse's own queries ----------

DBS = {"payments": 2.1e9, "orders": 6.4e9, "keycloak": 0.3e9, "postgres": 8e6}
# Many small databases on one server, like a shared QA instance
DBS.update({name: size for name, size in zip(
    ["billing", "inventory", "audit", "reports", "notifications", "search", "analytics", "crm", "scheduler", "lab", "pharmacy",
     "radiology", "bloodbank", "mirth", "rcm", "documents", "consent", "portal", "telemetry"],
    [10.7e9, 8.1e9, 1.0e9, 636e6, 382e6, 210e6, 4.4e9, 95e6, 31e6, 1.6e9, 720e6, 2.9e9, 22e6, 640e6, 380e6, 3.3e9, 12e6, 150e6, 1.2e9])})
DB_RATES = {"payments": 180, "orders": 90, "billing": 120, "analytics": 40, "reports": 15, "lab": 25}


def db_counters(db, up, scale=1.0):
    """Growing pg_stat_database counters; analytics misses the cache, reports spills to temp files, orders grows."""
    rate = DB_RATES.get(db, 2) * scale
    miss = 0.25 if db == "analytics" else 0.01
    return {"xact_commit": int(5e6 + rate * up), "xact_rollback": int(2e3 + rate * up / (40 if db == "billing" else 400)),
            "blks_hit": int(9e8 + rate * 60 * up), "blks_read": int(4e6 + rate * 60 * miss * up),
            "deadlocks": 30 if db == "billing" else 0, "temp_bytes": int(up * 2e6) if db == "reports" else 0,
            "size": int(DBS[db] + (up * 4e5 if db == "orders" else 0))}


def exporter_metrics(replica):
    """What postgres_exporter (port 9187) shows for the primary or the read replica, counters growing over time."""
    up = time.time() - STARTED
    lines = ['pg_up 1', 'pg_static{short_version="16.3.0",version="PostgreSQL 16.3"} 1', f"pg_settings_max_connections {200 if replica else 100}",
             f"pg_postmaster_start_time_seconds {STARTED - 86400 * 9}", f"pg_replication_is_replica {int(replica)}",
             f"pg_replication_lag_seconds {0.4 + 2 * random.random() if replica else 0}"]
    for db, size in DBS.items():
        busy = 0 if replica else {"payments": 3, "orders": 2}.get(db, 0)
        idle = (4 if replica else 10) if db in ("payments", "orders", "keycloak") else int(db in ("billing", "lab"))
        for state, n in (("active", busy), ("idle", idle), ("idle in transaction", 0)):
            lines.append(f'pg_stat_activity_count{{datname="{db}",state="{state}"}} {n if db != "postgres" else 0}')
        c = db_counters(db, up, 0.3 if replica else 1)
        lines += [f'pg_database_size_bytes{{datname="{db}"}} {c.pop("size")}']
        lines += [f'pg_stat_database_{k}{{datname="{db}"}} {v}' for k, v in c.items()]
    lines += ['pg_locks_count{datname="payments",mode="rowexclusivelock"} 6', 'pg_locks_count{datname="payments",mode="sharelock"} 1']
    return "\n".join(lines) + "\n"


STATEMENTS = [   # query, database, calls per second, mean ms
    ("SELECT o.id, o.status, o.total FROM orders o JOIN customers c ON c.id = o.customer_id WHERE c.email = $1 ORDER BY o.created_at DESC LIMIT $2", "orders", 14, 38.5),
    ("SELECT date_trunc($1, created_at) AS day, sum(total) FROM orders WHERE created_at >= $2 GROUP BY 1 ORDER BY 1", "orders", 0.02, 9120.0),
    ("UPDATE payments SET status = $1, updated_at = now() WHERE id = $2", "payments", 22, 4.2),
    ("INSERT INTO payment_events (payment_id, kind, payload) VALUES ($1, $2, $3)", "payments", 30, 1.1),
    ("SELECT * FROM payments WHERE merchant_id = $1 AND status = $2", "payments", 6, 212.0),
    ("SELECT count(*) FROM orders WHERE status = $1", "orders", 0.5, 1430.0),
    ("SELECT id, name, price FROM products WHERE id = ANY($1)", "orders", 40, 0.6),
    ("SELECT u.* FROM user_entity u WHERE u.realm_id = $1 AND u.username = $2", "keycloak", 3, 2.4),
    ("DELETE FROM sessions WHERE expires_at < now()", "payments", 0.01, 18200.0),
    ("SELECT p.*, m.name FROM payments p JOIN merchants m ON m.id = p.merchant_id WHERE p.created_at > $1", "payments", 1.2, 640.0),
]


def fake_sessions():
    """Connections from the fake pods: each app's pool, a slow report, an open transaction and a lock wait."""
    pods = {}
    for p in PODS:
        if p["metadata"]["namespace"] == "prod" and p["status"].get("podIP"):
            pods.setdefault(p["metadata"]["labels"]["app"], []).append(p["status"]["podIP"])
    rows, pid, up = [], 4100, time.time() - STARTED
    def add(app, ip, db, state, age, query, wait=None, blocked="", app_name="PostgreSQL JDBC Driver"):
        nonlocal pid
        pid += 1
        rows.append({"pid": pid, "datname": db, "usename": app.replace("-", "_"), "app": app_name, "addr": ip, "state": state,
                     "conn_age": 3000, "xact_age": age if state != "idle" else None, "query_age": age, "state_age": age,
                     "wait_event_type": wait and wait.split(":")[0], "wait_event": wait and wait.split(":")[1], "blocked_by": blocked, "query": query})
        return pid
    for app, db, per_pod in (("payments-api", "payments", 10), ("checkout", "orders", 8), ("billing", "payments", 5), ("catalog", "orders", 4), ("auth", "keycloak", 3)):
        for ip in pods.get(app, []):
            for k in range(per_pod):
                add(app, ip, db, "active" if k == 0 else "idle", 0.05 if k == 0 else 4, STATEMENTS[0][0] if db == "orders" else STATEMENTS[2][0])
    if pods.get("billing"):
        holder = add("billing", pods["billing"][0], "payments", "idle in transaction", 420 + up, "UPDATE payments SET status = 'settled' WHERE id = 99812")
        add("payments-api", (pods.get("payments-api") or ["10.0.0.1"])[0], "payments", "active", 95 + up, "UPDATE payments SET status = 'failed' WHERE id = 99812",
            wait="Lock:transactionid", blocked=f"{{{holder}}}")
    if pods.get("reports"):
        add("reports", pods["reports"][0], "orders", "active", 540 + up, STATEMENTS[1][0].replace("$1", "'day'").replace("$2", "'2026-01-01'"), wait="IO:DataFileRead")
    add("dba", "10.0.5.9", "orders", "idle", 1800, "select count(*) from orders", app_name="psql")
    return rows


def fake_sql(q):
    up = time.time() - STARTED
    if "server_version" in q:
        return [{"version": "16.3", "max_conn": "100", "uptime": str(int(86400 * 9 + up)), "replica": "f", "lag": "0"}]
    if "pg_stat_database" in q:
        return [{"datname": db, "numbackends": str({"payments": 13, "orders": 12, "billing": 9}.get(db, 1)),
                 **{k: str(v) for k, v in db_counters(db, up).items()}} for db in DBS]
    if "pg_stat_activity" in q:
        return fake_sessions()
    if "pg_stat_statements" in q:
        return [{"id": str(9000 + i), "datname": db, "usename": "app", "calls": str(int(cps * (40000 + up))), "total": str(cps * (40000 + up) * mean),
                 "mean": str(mean), "max": str(mean * 6), "rows": str(int(cps * 40000)), "hit": str(int(9e5 / (1 + mean / 50))), "rd": str(int(mean * 40)),
                 "tmp": "2048" if mean > 5000 else "0", "query": text} for i, (text, db, cps, mean) in enumerate(STATEMENTS)]
    return []


class FakePostgres(socketserver.BaseRequestHandler):
    """Just enough of the PostgreSQL wire protocol for KubePulse: no TLS, any password, canned rows."""
    def msg(self, kind, body):
        self.request.sendall(kind + struct.pack("!i", len(body) + 4) + body)

    def handle(self):
        f = self.request.makefile("rb")
        size = struct.unpack("!i", f.read(4))[0]
        if f.read(size - 4) == struct.pack("!i", 80877103):   # SSLRequest: no TLS here
            self.request.sendall(b"N")
            f.read(struct.unpack("!i", f.read(4))[0] - 4)
        self.msg(b"R", struct.pack("!i", 0))
        self.msg(b"Z", b"I")
        while True:
            head = f.read(5)
            if len(head) < 5 or head[:1] == b"X":
                return
            body = f.read(struct.unpack("!i", head[1:])[0] - 4)
            rows = fake_sql(body.decode())
            cols = list(rows[0]) if rows else []
            self.msg(b"T", struct.pack("!h", len(cols)) + b"".join(c.encode() + b"\0" + b"\0" * 18 for c in cols))
            for r in rows:
                vals = [None if r[c] is None else str(r[c]).encode() for c in cols]
                self.msg(b"D", struct.pack("!h", len(vals)) + b"".join(struct.pack("!i", -1) if v is None else struct.pack("!i", len(v)) + v for v in vals))
            self.msg(b"C", b"SELECT\0")
            self.msg(b"Z", b"I")


if __name__ == "__main__":
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    threading.Thread(target=socketserver.ThreadingTCPServer(("127.0.0.1", 8914), FakePostgres).serve_forever, daemon=True).start()
    for port, handler in ((8912, Model), (8913, Webhook)):
        threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever, daemon=True).start()
    print("fake Kubernetes API on :8911, model on :8912, Mattermost webhook on :8913, PostgreSQL on :8914", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8911), Kubernetes).serve_forever()
