"""Ownership and time budget for the stress client (standard library only)."""
import json
import os
import tempfile
import threading
import time
import uuid


class BudgetExpired(RuntimeError):
    pass


class Safety:
    def __init__(self, duration=None, cleanup_grace=180):
        self.identity = 'st' + uuid.uuid4().hex
        self.deadline = time.monotonic() + duration if duration else None
        self.cleanup_grace = cleanup_grace
        self.cleaning = False
        self.owned = {}
        self.intents = []
        self.unresolved = False
        self.lock = threading.RLock()
        fd, self.receipt = tempfile.mkstemp(prefix='briqyard-stress-', suffix='.json')
        os.close(fd)  # mkstemp creates mode 0600; contains identifiers only.
        self.save()

    def save(self):
        with self.lock:
            fd, temporary = tempfile.mkstemp(dir=os.path.dirname(self.receipt), prefix='.stress-')
            with os.fdopen(fd, 'w') as f:
                json.dump(dict(run=self.identity, accepted=self.owned,
                               intents=self.intents, unresolved=self.unresolved), f)
            os.replace(temporary, self.receipt)

    def cap(self, seconds):
        if self.deadline is None:
            return seconds
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BudgetExpired('stress time budget exhausted')
        return min(seconds, remaining)

    def sleep(self, seconds):
        time.sleep(self.cap(seconds))

    def begin_cleanup(self):
        if not self.cleaning:
            self.cleaning = True
            self.deadline = time.monotonic() + self.cleanup_grace

    def matches(self, m):
        return self.owned.get(m.get('id')) == [m.get('namespace'), m.get('name')] and (m.get('metadata') or {}).get('stress') == self.identity

    def verify(self, send, mid, timeout, missing_ok=False):
        status, text = send('GET', f'/v1/machines/{mid}', op='verify ownership', timeout=self.cap(timeout))
        if status == 404 and missing_ok:
            with self.lock:
                self.owned.pop(mid, None)
                self.save()
            return False
        machine = json.loads(text) if status == 200 else None
        if (not isinstance(machine, dict) or machine.get('id') != mid
                or not self.matches(machine)):
            raise RuntimeError('ownership unknown or changed; preserving machine')
        return True

    def request(self, send, method, path, body=None, op=None, timeout=300):
        timeout = self.cap(timeout)
        create = method == 'POST' and path == '/v1/machines'
        mutation = method not in ('GET', 'HEAD')
        if mutation and not self.cleaning and self.unresolved:
            raise RuntimeError('ambiguous create; further workload mutations disabled')
        if mutation and path.startswith('/v1/namespaces/'):
            raise RuntimeError('namespace mutation cannot prove exclusive ownership')
        mid = None
        if mutation and path.startswith('/v1/machines/'):
            mid = path.split('/')[3].split('?')[0]
            if not self.verify(send, mid, timeout, missing_ok=method == 'DELETE'):
                return 204, ''
        if create:
            body = dict(body, metadata=dict(body.get('metadata', {}), stress=self.identity))
            intent = [body['namespace'], body['name']]
            for source in ('fork', 'restore'):
                if source in body:
                    self.verify(send, body[source]['machine_id'], timeout)
            status, text = send('GET', '/v1/machines', op='check create name', timeout=self.cap(timeout))
            if status != 200:
                raise RuntimeError('cannot establish create name is unused')
            if any([m.get('namespace'), m.get('name')] == intent for m in json.loads(text)):
                raise RuntimeError('create name already exists; preserving machine')
            # Only bookkeeping is serialized. These intents authorize already in-flight
            # requests to settle even if another request subsequently becomes ambiguous.
            with self.lock:
                if self.unresolved:
                    raise RuntimeError('ambiguous create; further creates disabled')
                if intent in self.intents:
                    raise RuntimeError('create name already in flight')
                self.intents.append(intent)
                self.save()
            try:
                send_timeout = self.cap(timeout)
            except BudgetExpired:
                with self.lock:
                    self.intents.remove(intent)
                    self.save()
                raise
            try:
                status, text = send(method, path, body, op, send_timeout)
                m = json.loads(text) if 200 <= status < 300 else None
                if (not isinstance(m, dict) or not isinstance(m.get('id'), str)
                        or not m['id'] or [m.get('namespace'), m.get('name')] != intent
                        or (m.get('metadata') or {}).get('stress') != self.identity):
                    raise RuntimeError('ambiguous or inconsistent create response')
                with self.lock:
                    if m['id'] in self.owned:
                        raise RuntimeError('create returned an already accepted ID')
                    self.owned[m['id']] = intent
                    self.intents.remove(intent)
                    self.save()
                return status, text
            except BaseException:
                with self.lock:
                    self.unresolved = True
                    self.save()
                raise
        # Recheck after ownership reads, before starting any new workload mutation.
        if mutation and not self.cleaning and self.unresolved:
            raise RuntimeError('ambiguous create; further workload mutations disabled')
        status, text = send(method, path, body, op, self.cap(timeout))
        if method == 'DELETE' and mid and path == f'/v1/machines/{mid}' and 200 <= status < 300:
            with self.lock:
                self.owned.pop(mid, None)
                self.save()
        return status, text
