"""A fake cluster for developing KubePulse without a real one.

Serves a small Kubernetes API (with failing pods, events, logs, workloads, services, volumes,
certificates and a Prometheus), a scripted OpenAI-compatible model and a Mattermost webhook
that prints what it receives.

    python3 dev/fake_cluster.py
    K8S_API=http://127.0.0.1:8911 DATA_DIR=/tmp OPENAI_API_KEY=x OPENAI_BASE_URL=http://127.0.0.1:8912/v1 \\
      MATTERMOST_WEBHOOK_URL=http://127.0.0.1:8913/hook python3 app.py
"""
import json
import os
import random
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

random.seed(7)
NOW = datetime.now(timezone.utc)
ts = lambda sec: (NOW - timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
future = lambda sec: (NOW + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
HOOK_LOG = os.getenv("HOOK_LOG", "")

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
        if path == "/api/v1/events":
            return self.send({"items": [e for e in EVENTS if e["type"] == "Warning"]})
        if path == "/api/v1/services":
            return self.send({"items": [{"metadata": {"name": n, "namespace": ns}, "spec": {"type": "ClusterIP", "ports": [{"port": port, "name": "web"}]}}
                                        for ns, n, port in (("prod", "api", 80), ("monitoring", "prometheus-operated", 9090),
                                                            ("monitoring", "prometheus-prometheus-node-exporter", 9100))]})
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


if __name__ == "__main__":
    for port, handler in ((8912, Model), (8913, Webhook)):
        threading.Thread(target=ThreadingHTTPServer(("127.0.0.1", port), handler).serve_forever, daemon=True).start()
    print("fake Kubernetes API on :8911, model on :8912, Mattermost webhook on :8913", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8911), Kubernetes).serve_forever()
