#!/usr/bin/env python3
"""Proves what the running Grafana will post alerts to, without waiting for an alert.

Reads Grafana's effective Slack contact point (the provisioning export, decrypted) and compares
its URL with SLACK_WEBHOOK_URL in /etc/briqyard-monitoring/alerting.env. Differs, or not an
https:// URL: it fails and says to run hack/install-monitoring.sh again. Nothing is sent. The
URLs are never printed.

  python3 hack/monitoring-webhook-check.py          # the admin password: stdin, or GRAFANA_PASSWORD_FILE
  python3 hack/monitoring-webhook-check.py --send   # also Grafana's own test of the contact point:
                                                    # ONE test message to the real channel

Settings: GRAFANA_LISTEN (127.0.0.1:3000), ALERTING_ENV (/etc/briqyard-monitoring/alerting.env),
ALLOW_INSECURE_WEBHOOK=1 (accept http://, for a test receiver).
"""
import base64
import getpass
import json
import os
import sys
import time
import urllib.error
import urllib.request

LISTEN = os.environ.get("GRAFANA_LISTEN", "127.0.0.1:3000")
ENV_FILE = os.environ.get("ALERTING_ENV", "/etc/briqyard-monitoring/alerting.env")
NAME = "briqyard slack"  # the contact point of hack/monitoring/grafana/alerting.yaml
UID = "briqyard-slack"


def fail(msg):
    print(f"FAIL {msg}", flush=True)
    sys.exit(1)


def wanted():
    """SLACK_WEBHOOK_URL as the unit's EnvironmentFile gives it to Grafana: the last assignment."""
    value = None
    try:
        for line in open(ENV_FILE):
            if line.startswith("SLACK_WEBHOOK_URL="):
                value = line.rstrip("\n")[len("SLACK_WEBHOOK_URL="):]
    except OSError as e:
        fail(f"cannot read {ENV_FILE}: {e.strerror}")
    if value and len(value) > 1 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not value:
        fail(f"{ENV_FILE} has no SLACK_WEBHOOK_URL")
    return value


def scheme_ok(url):
    return url.startswith("https://") or (os.environ.get("ALLOW_INSECURE_WEBHOOK") == "1" and url.startswith("http://"))


def password():
    if os.environ.get("GRAFANA_PASSWORD_FILE"):
        return open(os.environ["GRAFANA_PASSWORD_FILE"]).readline().rstrip("\n")
    if not sys.stdin.isatty():
        return sys.stdin.readline().rstrip("\n")
    return getpass.getpass("Grafana admin password: ")


def call(method, path, auth, body=None):
    req = urllib.request.Request(f"http://{LISTEN}{path}", method=method, data=None if body is None else json.dumps(body).encode())
    req.add_header("Authorization", auth)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def effective(auth):
    """The URL of the contact point as Grafana holds it. A minute for provisioning to have run."""
    for _ in range(30):
        try:
            status, text = call("GET", "/api/v1/provisioning/contact-points/export?decrypt=true&format=json", auth)
        except OSError:
            status, text = 0, ""
        if status == 401:
            fail("Grafana refused the admin password")
        if status == 200:
            for cp in json.loads(text).get("contactPoints", []):
                for r in cp.get("receivers", []):
                    if r.get("uid") == UID:
                        return r.get("settings", {}).get("url", "")
        time.sleep(2)
    fail(f"Grafana at {LISTEN} has no contact point {UID!r} (alerting off, or Grafana not answering)")


def main():
    send = "--send" in sys.argv[1:]
    want = wanted()
    if not scheme_ok(want):
        fail(f"SLACK_WEBHOOK_URL in {ENV_FILE} is not an https:// URL")
    auth = "Basic " + base64.b64encode(f"admin:{password()}".encode()).decode()
    have = effective(auth)
    if have != want:
        fail(f"Grafana will post to a different URL than {ENV_FILE} (it holds "
             f"{'another URL' if scheme_ok(have) else 'a value that is not an https:// URL'}); "
             "run hack/install-monitoring.sh again")
    print("ok   Grafana's Slack contact point holds the webhook of alerting.env", flush=True)
    if not send:
        print("     nothing sent; --send has Grafana send one test message", flush=True)
        return
    rid = base64.urlsafe_b64encode(NAME.encode()).decode().rstrip("=")
    status, text = call("POST", f"/apis/notifications.alerting.grafana.app/v1beta1/namespaces/default/receivers/{rid}/test", auth,
                        {"integration": {"uid": UID, "type": "slack", "version": "v1", "settings": {}, "secureFields": {"url": True}}})
    if status != 200 or json.loads(text).get("status") != "success":
        fail(f"Grafana's test of the contact point failed ({status}): {text.replace(have, '<webhook>')[:300]}")
    print("ok   Grafana delivered a test message to the webhook", flush=True)


if __name__ == "__main__":
    main()
