// Standalone conformance consumer for the sealed v3.1 wire (SYL-268). Not an SDK: it reads
// ../../testdata/sealed_v3_1/vectors.json and reproduces every published value from first
// principles with Node's built-in crypto, using only erasable TypeScript syntax so that
// `node conformance.ts` runs it directly (Node >= 22.18). The Ed25519 seeds are RFC 8032
// section 7.1 test vectors: public test material that signs nothing real.

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Obj = { [key: string]: Json };

const MAX_SAFE = 9007199254740991;
const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath =
  process.env.SEALED_VECTORS ?? join(here, "..", "..", "testdata", "sealed_v3_1", "vectors.json");
const V: any = JSON.parse(readFileSync(vectorsPath, "utf8"));

let checks = 0;
const failures: string[] = [];
function check(name: string, ok: boolean): void {
  checks++;
  if (!ok) failures.push(name);
}
function equal(name: string, actual: unknown, expected: unknown): void {
  check(name, actual === expected);
  if (actual !== expected) console.error(`  ${name}: got ${String(actual)} want ${String(expected)}`);
}
function rejects(name: string, fn: () => unknown): void {
  let refused = false;
  try {
    fn();
  } catch {
    refused = true;
  }
  check(name, refused);
}

// ---- scalars -------------------------------------------------------------------------
const sha = (b: Buffer | string): Buffer => createHash("sha256").update(b).digest();
const hex = (b: Buffer | string): string => sha(b).toString("hex");

function b64uEncode(raw: Buffer): string {
  return raw.toString("base64url");
}
function b64uDecode(text: string, length: number): Buffer {
  const raw = Buffer.from(text, "base64url");
  if (raw.length !== length || b64uEncode(raw) !== text || !/^[A-Za-z0-9_-]+$/.test(text)) {
    throw new Error("base64url");
  }
  return raw;
}
const fill = (k: number): string => b64uEncode(Buffer.alloc(32, k));

// ---- C(t): strict canonical JSON ------------------------------------------------------
const plain = (c: number): boolean => c >= 0x20 && c <= 0x7e && c !== 0x22 && c !== 0x5c;

function writeString(s: string): string {
  for (let i = 0; i < s.length; i++) if (!plain(s.charCodeAt(i))) throw new Error("string alphabet");
  return '"' + s + '"';
}

function encodeValue(v: Json, depth: number): string {
  if (v === null) return "null";
  if (v === true) return "true";
  if (v === false) return "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v) || v < 0 || v > MAX_SAFE || Object.is(v, -0)) throw new Error("integer");
    return String(v);
  }
  if (typeof v === "string") return writeString(v);
  if (depth > 24) throw new Error("depth");
  if (Array.isArray(v)) {
    if (v.length > 256) throw new Error("array");
    return "[" + v.map((e) => encodeValue(e, depth + 1)).join(",") + "]";
  }
  const keys = Object.keys(v).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return "{" + keys.map((k) => writeString(k) + ":" + encodeValue(v[k], depth + 1)).join(",") + "}";
}

function C(v: Obj): Buffer {
  const out = Buffer.from(encodeValue(v, 1), "ascii");
  if (out.length > 65536) throw new Error("too large");
  return out;
}
const H = (v: Obj): string => hex(C(v));

class Parser {
  b: Buffer;
  at = 0;
  constructor(b: Buffer) {
    this.b = b;
  }
  peek(): number {
    return this.at < this.b.length ? this.b[this.at] : -1;
  }
  expect(c: number): void {
    if (this.peek() !== c) throw new Error("unexpected byte");
    this.at++;
  }
  word(w: string, v: Json): Json {
    if (this.b.subarray(this.at, this.at + w.length).toString("ascii") !== w) throw new Error("literal");
    this.at += w.length;
    return v;
  }
  value(depth: number): Json {
    const c = this.peek();
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.word("true", true);
    if (c === 0x66) return this.word("false", false);
    if (c === 0x6e) return this.word("null", null);
    if (c >= 0x30 && c <= 0x39) return this.integer();
    throw new Error("unexpected byte");
  }
  integer(): number {
    const start = this.at;
    while (this.peek() >= 0x30 && this.peek() <= 0x39) this.at++;
    const digits = this.b.subarray(start, this.at).toString("ascii");
    if ([0x2e, 0x65, 0x45].includes(this.peek())) throw new Error("float or exponent");
    if (digits.length > 1 && digits[0] === "0") throw new Error("leading zero");
    if (digits.length > 16) throw new Error("range");
    const n = Number(digits);
    if (n > MAX_SAFE) throw new Error("range");
    return n;
  }
  string(): string {
    this.expect(0x22);
    const start = this.at;
    for (;;) {
      const c = this.peek();
      if (c < 0) throw new Error("unterminated");
      if (c === 0x22) break;
      if (!plain(c)) throw new Error("string alphabet");
      this.at++;
    }
    const s = this.b.subarray(start, this.at).toString("ascii");
    this.at++;
    return s;
  }
  array(depth: number): Json[] {
    if (depth > 24) throw new Error("depth");
    this.expect(0x5b);
    const items: Json[] = [];
    if (this.peek() === 0x5d) {
      this.at++;
      return items;
    }
    for (;;) {
      if (items.length >= 256) throw new Error("array");
      items.push(this.value(depth + 1));
      const c = this.peek();
      this.at++;
      if (c === 0x5d) return items;
      if (c !== 0x2c) throw new Error("unexpected byte");
    }
  }
  object(depth: number): Obj {
    if (depth > 24) throw new Error("depth");
    this.expect(0x7b);
    const entries: [string, Json][] = [];
    if (this.peek() === 0x7d) {
      this.at++;
      return {};
    }
    let previous: string | null = null;
    for (;;) {
      const key = this.string();
      if (previous !== null) {
        if (previous === key) throw new Error("duplicate key");
        if (previous > key) throw new Error("unsorted keys");
      }
      this.expect(0x3a);
      entries.push([key, this.value(depth + 1)]);
      previous = key;
      const c = this.peek();
      this.at++;
      if (c === 0x7d) return Object.fromEntries(entries);
      if (c !== 0x2c) throw new Error("unexpected byte");
    }
  }
}

/** Parse raw bytes strictly and require byte equality with C of the parsed value. */
function decodeCanonical(bytes: Buffer): Obj {
  if (bytes.length > 65536 || bytes[0] !== 0x7b) throw new Error("not an object");
  const p = new Parser(bytes);
  const v = p.value(1) as Obj;
  if (p.at !== bytes.length) throw new Error("trailing bytes");
  if (!C(v).equals(bytes)) throw new Error("not canonical");
  return v;
}
const decodeText = (text: string): Obj => decodeCanonical(Buffer.from(text, "latin1"));

// ---- Sig(tag, T) ----------------------------------------------------------------------
const SPKI = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8 = Buffer.from("302e020100300506032b657004220420", "hex");

interface Key {
  raw: Buffer;
  kid: string;
  seed: Buffer;
}
function key(name: string): Key {
  const k = V.keys[name];
  const seed = Buffer.from(k.seed_hex, "hex");
  const priv = createPrivateKey({ key: Buffer.concat([PKCS8, seed]), format: "der", type: "pkcs8" });
  const raw = createPublicKey(priv).export({ format: "der", type: "spki" }).subarray(SPKI.length);
  equal(`${name} public key`, b64uEncode(raw), k.public);
  return { raw, kid: hex(raw), seed };
}
const pub = (raw: Buffer) => createPublicKey({ key: Buffer.concat([SPKI, raw]), format: "der", type: "spki" });
const signer = (k: Key) =>
  createPrivateKey({ key: Buffer.concat([PKCS8, k.seed]), format: "der", type: "pkcs8" });

function preimage(tag: string, kid: string, body: Obj): Buffer {
  return Buffer.concat([
    Buffer.from(V.domain, "ascii"),
    Buffer.from([0]),
    Buffer.from(tag, "ascii"),
    Buffer.from([0]),
    Buffer.from(kid, "ascii"),
    Buffer.from([0]),
    C(body),
  ]);
}

function signEnvelope(tag: string, body: Obj, k: Key): Obj {
  const sig = sign(null, preimage(tag, k.kid, body), signer(k));
  return { tag, kid: k.kid, body, sig: b64uEncode(sig) };
}

/** Decode an envelope from raw bytes: canonical C, exactly {tag,kid,body,sig}, strict encodings. */
function decodeEnvelope(bytes: Buffer): Obj {
  const env = decodeCanonical(bytes);
  if (Object.keys(env).join(",") !== "body,kid,sig,tag") throw new Error("envelope shape");
  if (!/^[0-9a-f]{64}$/.test(env.kid as string)) throw new Error("kid");
  b64uDecode(env.sig as string, 64);
  if (typeof env.tag !== "string" || typeof env.body !== "object" || env.body === null) throw new Error("envelope shape");
  return env;
}

/** Decode an envelope from raw bytes and verify it under one pinned key and expected tag. */
function verifyEnvelope(bytes: Buffer, expectedTag: string, pinned: Key): Obj {
  const env = decodeEnvelope(bytes);
  const sig = b64uDecode(env.sig as string, 64);
  if (env.tag !== expectedTag) throw new Error("wrong tag");
  if (env.kid !== pinned.kid) throw new Error("wrong key");
  if (!verify(null, preimage(env.tag as string, env.kid as string, env.body as Obj), pub(pinned.raw), sig)) {
    throw new Error("bad signature");
  }
  return env;
}

// ---- shared fixtures ------------------------------------------------------------------
const rk = key("rk");
const bk = key("bk");
const ak = key("ak");
equal("rk kid is h(raw public key)", rk.kid, V.keys.rk.kid);

const PLAN = V.plan_hash_fill.repeat(64);
const X: Obj = { aud: V.x.aud, host: V.x.host, op: V.x.op_fill.repeat(64), serial: V.x.serial };
const proc = (pid: number): Obj => ({
  boot: V.proc.boot,
  build: V.proc.build,
  exe: V.proc.exe_digit.repeat(64),
  pid,
  start: V.proc.start,
});

// ---- 1. query.host envelope -----------------------------------------------------------
{
  const q = V.query;
  const body = decodeText(q.body);
  equal("query body is exactly C(body)", C(body).toString("latin1"), q.body);
  const reordered = { preview: null, plan: PLAN, q: { x: { serial: 1, op: X.op, host: X.host, aud: X.aud }, nonce: fill(0) } };
  equal("reordering before encoding gives the same bytes", C(reordered as Obj).toString("latin1"), q.body);
  equal("signature preimage hash", hex(preimage(q.tag, rk.kid, body)), q.preimage_hash);
  const env = signEnvelope(q.tag, body, rk);
  equal("signature", env.sig, q.sig);
  equal("H(envelope)", H(env), q.envelope_hash);
  const text = C(env);
  verifyEnvelope(text, q.tag, rk);
  check("envelope verifies under the pinned Rk", true);
  rejects("keys swapped on the wire: pinned Bk refuses an Rk envelope", () => verifyEnvelope(text, q.tag, bk));
  rejects("a different expected tag refuses", () => verifyEnvelope(text, "query.authority", rk));
  for (const n of q.negatives) {
    let mutated = text.toString("latin1");
    if (n.append !== undefined) mutated += n.append;
    else {
      check(`${n.id}: fixture contains the text to mutate`, mutated.includes(n.find));
      mutated = mutated.replace(n.find, n.replace);
    }
    const bytes = Buffer.from(mutated, "latin1");
    if (n.expect === "decode") {
      rejects(`negative ${n.id} fails raw-byte decoding`, () => decodeEnvelope(bytes));
      rejects(`negative ${n.id} never verifies`, () => verifyEnvelope(bytes, q.tag, rk));
    } else {
      decodeEnvelope(bytes);
      rejects(`negative ${n.id} refuses under the expected tag`, () => verifyEnvelope(bytes, q.tag, rk));
      rejects(`negative ${n.id} refuses under its own tag (signature does not cover it)`, () =>
        verifyEnvelope(bytes, (decodeCanonical(bytes).tag as string), rk),
      );
    }
  }
}

// ---- 2. native registration, ACK and the C(H(Reg)) distinction --------------------------
{
  const r = V.native_reg;
  const reg = JSON.parse(r.text);
  const native = Buffer.from(
    JSON.stringify({
      authority: reg.authority,
      epoch: reg.epoch,
      key_id: reg.key_id,
      public_key: reg.public_key,
      host_instance: reg.host_instance,
      generation: reg.generation,
    }),
    "ascii",
  );
  equal("native bytes are the six fields in displayed order", native.toString("ascii"), r.text);
  equal("public_key is the Rk key", Buffer.from(reg.public_key).equals(rk.raw), true);
  equal("legacy reg_hash is SHA-256 of the native bytes", hex(native), r.reg_hash);
  const ack = { host_instance: reg.host_instance, generation: reg.generation, digest: b64uEncode(sha(native)) };
  equal("Ack.digest", ack.digest, r.ack_digest);
  equal("ctx.reg_hash is the same digest in hex", Buffer.from(b64uDecode(ack.digest, 32)).toString("hex"), r.reg_hash);

  const canonical = C(reg);
  check("C(Reg) is sorted, not native order", canonical.toString("ascii").startsWith(r.canonical_prefix));
  check("C(Reg) differs from the native bytes", !canonical.equals(native));
  equal("H(Reg) under canonical order", hex(canonical), r.canonical_h_reg);
  check("H(Reg) is not the native digest", hex(canonical) !== r.reg_hash);
  rejects("legacy order is refused wherever C is required", () => decodeCanonical(native));
  equal("canonical order decodes", Buffer.from(JSON.stringify(decodeCanonical(canonical).public_key)).length > 0, true);
}

// ---- 3. trial: C(Trial), commitments, approvals, issuance, status -----------------------
const T = V.trial;
const trial = decodeText(T.c);
equal("C(Trial) is the exact canonical bytes", C(trial).toString("latin1"), T.c);
equal("H(Trial)", H(trial), T.hash);
{
  const originHash = hex(Buffer.concat([Buffer.from("briqyard/trial-origin/v3", "ascii"), Buffer.from([0]), Buffer.from(T.origin, "ascii")]));
  equal("gateway_origin_hash", originHash, T.origin_hash);
  equal("Trial.gateway_origin_hash", trial.gateway_origin_hash, originHash);

  const u = (n: number): Buffer => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64BE(BigInt(n));
    return b;
  };
  const s = (t: string): Buffer => Buffer.concat([u(Buffer.byteLength(t, "utf8")), Buffer.from(t, "utf8")]);
  const nonce = trial.nonce as string;
  const preimageBytes = Buffer.concat([
    Buffer.from("briqyard-exec-request-v1", "ascii"),
    Buffer.from([0]),
    u(4),
    s("/bin/busybox"),
    s("printf"),
    s("%s"),
    s(nonce),
    u(0),
    s(""),
    s(""),
    u(1000),
  ]);
  equal("command preimage", preimageBytes.toString("hex"), T.command_preimage_hex);
  equal("command_hash", hex(preimageBytes), T.command_hash);
  equal("Trial.command_hash", trial.command_hash, T.command_hash);
  equal("native request_digest is the same 32 bytes in base64url", b64uEncode(sha(preimageBytes)), T.native_request_digest);
  equal("request JSON", C({ cmd: ["/bin/busybox", "printf", "%s", nonce], cwd: "", env: {}, stdin: "", timeout_ms: 1000, wake: false }).toString("ascii"), T.request_json);

  const ra = signEnvelope("trial3.receiver", trial, rk);
  const ba = signEnvelope("trial3.api", trial, bk);
  equal("H(RA)", H(ra), T.ra_hash);
  equal("H(BA)", H(ba), T.ba_hash);
  rejects("swapped approval keys refuse", () => verifyEnvelope(C(signEnvelope("trial3.receiver", trial, bk)), "trial3.receiver", rk));
  const swappedDelegation = { ...trial, delegation_intent: trial.grant_id };
  check("using grant_id as delegation_intent changes the commitment", H(swappedDelegation) !== T.hash);

  equal("grant_hash", hex(Buffer.from(T.grant_text, "ascii")), T.grant_hash);
  equal("projection_hash", hex(Buffer.from(T.projection_text, "ascii")), T.projection_hash);
  const issued = signEnvelope("trial3.issued", { trial: H(trial), grant_hash: T.grant_hash, projection_hash: T.projection_hash }, bk);
  equal("H(Issued)", H(issued), T.issued_hash);
  equal("H(Job)", H({ approvals: { api: ba, receiver: ra }, issued }), T.job_hash);

  equal("outcome", hex(Buffer.from(T.outcome_preimage, "ascii")), T.outcome);
  equal("outcome preimage is native field order", T.outcome_preimage, JSON.stringify({ stdout: nonce, stderr: "", exit_code: 0, timed_out: false }));

  const status = (fillByte: number): Obj =>
    signEnvelope(
      "trial3.status",
      {
        q: { nonce: fill(fillByte), x: X },
        plan: PLAN,
        trial: H(trial),
        proc: proc(18),
        bind_hash: trial.bind_hash,
        run: trial.run,
        grant_id: trial.grant_id,
        delegation_intent: trial.delegation_intent,
        request_hash: trial.command_hash,
        grant_hash: T.grant_hash,
        projection_hash: T.projection_hash,
        phase: "finished",
        outcome: T.outcome,
      },
      ak,
    );
  const sb = status(T.status_b_nonce_fill);
  const sr = status(T.status_r_nonce_fill);
  equal("B-challenged Ak signature", sb.sig, T.status_b_sig);
  equal("H(B-challenged status)", H(sb), T.status_b_hash);
  equal("H(R-challenged status)", H(sr), T.status_r_hash);
  check("the two verifiers' status envelopes differ", H(sb) !== H(sr));
  equal("final.read.trial is H of the complete B-challenged status", H(sb), T.final_read_trial);
  equal("client.enable.trial is H(Trial), never H(Status)", H(trial), T.client_enable_trial);
  check("client.enable.trial differs from final.read.trial", T.client_enable_trial !== T.final_read_trial);
  verifyEnvelope(C(sb), "trial3.status", ak);
  rejects("a status never verifies under Rk", () => verifyEnvelope(C(sb), "trial3.status", rk));

  const t = T.timeout;
  const allowed = (nowMs: number): bigint => {
    const room = 1000n * BigInt(t.exp) - BigInt(nowMs) - 1000n;
    const candidates = [1000n, 60000n, 1000n * BigInt(t.max_duration_seconds), room];
    return candidates.reduce((a, b) => (a < b ? a : b));
  };
  equal("timeout: nowMs 1999999998000 sends exactly 1000", allowed(t.send.now_ms), 1000n);
  equal("timeout: nowMs 1999999998001 has room 999", allowed(t.refuse.now_ms), BigInt(t.refuse.room));
  check("timeout: 999 ms is refused, never sent shortened", allowed(t.refuse.now_ms) !== 1000n);
}

// ---- 4. custody fixture ------------------------------------------------------------------
{
  const c = V.custody;
  const wire = (extra: Obj): Obj => ({
    x: X,
    plan: PLAN,
    resource: c.capture.resource,
    owner: fill(c.capture.owner_fill),
    custodian: proc(c.capture.custodian_pid),
    old: proc(c.capture.old_pid),
    next: null,
    challenge: fill(c.capture.challenge_fill),
    slot: c.capture.slot,
    ...extra,
  });
  const capture = signEnvelope("custody.capture", { wire: wire({}) }, rk);
  const request = wire({ next: proc(c.request.next_pid), challenge: fill(c.request.challenge_fill) });
  const matched = signEnvelope("custody.match", { wire: request, capture: H(capture), same: true }, rk);
  const exited = signEnvelope("custody.exit", { wire: request, match: H(matched), exited: true }, rk);
  equal("H(Capture)", H(capture), c.capture_hash);
  equal("H(Rk signed matched)", H(matched), c.matched_hash);
  equal("H(Rk signed exited)", H(exited), c.exited_hash);
  equal("matched and exited repeat the same wire", C(matched.body as Obj).includes(C({ wire: request }).subarray(1, -1)), true);
  const other = (extra: Obj): string => H(signEnvelope("custody.match", { wire: { ...request, ...extra }, capture: H(capture), same: true }, rk));
  for (const [name, extra] of [
    ["owner", { owner: fill(9) }],
    ["challenge", { challenge: fill(4) }],
    ["slot", { slot: 28 }],
    ["no returned successor", { next: null }],
  ] as [string, Obj][]) {
    check(`a different ${name} is a different match, never the published one`, other(extra) !== c.matched_hash);
  }
}

if (failures.length > 0) {
  console.error(`FAILED ${failures.length} of ${checks} checks:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log(`typescript conformance: ${checks} checks passed`);
