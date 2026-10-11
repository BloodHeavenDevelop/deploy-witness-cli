#!/usr/bin/env python3
"""Sanitise one raw scenario run for docs/site-materials/outputs/ (DW-73).

    sanitize.py <context.json> <raw scenario dir> <output dir>

Two operations, nothing else:

1. Trim — host-wide inventories that have nothing to do with the scenario are
   cut down to the rows that do: listening sockets to the scenario's port, and in
   report.json the containers, networks, volumes, images, scheduled jobs and
   databases of the machine that ran it. What was removed is counted in
   TRIMMED.md. Findings, evidence, notes, changes, rollback, network and the
   command journal are never trimmed.
2. Replace — values that identify the machine are swapped for marked
   placeholders, consistently across every file of every scenario:
   <WORKDIR>, <HOME>, <USER>, <HOSTNAME>, <HOST-IPV4-n>, <HOST-IPV6-n>,
   <SERVER-FINGERPRINT>, <host-image-NN>, <host-image-id-NN>,
   <host-network-NN>, <host-volume-NN>, <host-container-NN>.

Everything else is the tool's output byte for byte (CSV files are rewritten
only when a row was trimmed or a value replaced).
"""
import csv
import io
import json
import os
import re
import sys


def placeholder_map(ctx):
    pairs = []
    pairs.append((ctx["workdir"], "<WORKDIR>"))
    pairs.append((ctx["home"], "<HOME>"))

    def numbered(values, label, keep=()):
        n = 0
        for v in sorted(set(values)):
            if v in keep:
                continue
            n += 1
            pairs.append((v, f"<{label}-{n:02d}>"))
            if label == "host-image" and ":" in v:
                # app/redact rewrites some tags (known defect DW-45).
                pairs.append((v.rsplit(":", 1)[0] + ":***redacted***", f"<{label}-{n:02d}>"))

    numbered(ctx["images"], "host-image", ctx["keep_images"])
    numbered(ctx["image_ids"], "host-image-id", ctx["keep_image_ids"])
    numbered(ctx["networks"], "host-network", ctx["keep_networks"])
    numbered(ctx["volumes"], "host-volume")
    numbered(ctx["containers"], "host-container")
    v4 = v6 = 0
    for a in ctx["addresses"]:
        if ":" in a:
            v6 += 1
            pairs.append((a, f"<HOST-IPV6-{v6}>"))
        else:
            v4 += 1
            pairs.append((a, f"<HOST-IPV4-{v4}>"))
    pairs.append((ctx["hostname"], "<HOSTNAME>"))
    pairs.append((ctx["user"], "<USER>"))
    return pairs


def compile_replacer(pairs, fingerprint):
    table = {}
    for k, v in pairs:
        table.setdefault(k, v)
    keys = sorted(table, key=len, reverse=True)
    # A name only matches as a whole token: not inside a longer image, path
    # segment or word ("redis" must not hit "redis-cli").
    rx = re.compile(r"(?<![\w.:/-])(" + "|".join(re.escape(k) for k in keys) + r")(?![\w.-])")
    paths = [(k, table[k]) for k in keys if k.startswith("/")]

    def replace(text):
        for k, v in paths:  # paths first and anywhere: they prefix other paths
            text = text.replace(k, v)
        text = rx.sub(lambda m: table[m.group(1)], text)
        if fingerprint:
            text = text.replace(fingerprint, "<SERVER-FINGERPRINT>")
        return text

    return replace


def trim_report(doc, ctx, notes):
    keep_ports = set(ctx["keep_ports"])
    audit = doc.get("audit") or {}
    caps = audit.get("capabilities") or {}

    def cut(holder, key, keep, label):
        rows = holder.get(key)
        if not isinstance(rows, list):
            return
        kept = [r for r in rows if keep(r)]
        if len(kept) != len(rows):
            notes.append(f"report.json `{label}`: kept {len(kept)} of {len(rows)} entries")
        holder[key] = kept

    ours = {"orders-api", "dwkit-data", "dwkit-net"}  # what run.sh creates
    cut(audit, "ports", lambda r: r.get("port") in keep_ports, "audit.ports")
    cut(caps, "ports", lambda r: r.get("port") in keep_ports, "audit.capabilities.ports")
    cut(caps, "containers", lambda r: r.get("name") in ours, "audit.capabilities.containers")
    cut(caps, "containerNetworks", lambda r: r.get("name") in ctx["keep_networks"] or r.get("name") in ours, "audit.capabilities.containerNetworks")
    cut(caps, "containerVolumes", lambda r: r.get("name") in ours, "audit.capabilities.containerVolumes")
    cut(caps, "images", lambda r: r.get("reference") in ctx["keep_images"], "audit.capabilities.images")
    cut(caps, "jobs", lambda r: False, "audit.capabilities.jobs")
    cut(caps, "databases", lambda r: False, "audit.capabilities.databases")


def trim_ports_csv(text, ctx, notes):
    rows = list(csv.reader(io.StringIO(text)))
    if not rows:
        return text
    head, body = rows[0], rows[1:]
    col = head.index("Port")
    kept = [r for r in body if r[col].isdigit() and int(r[col]) in ctx["keep_ports"]]
    if len(kept) == len(body):
        return text
    notes.append(f"ports.csv: kept {len(kept)} of {len(body)} rows (the sockets on port 8080)")
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\r\n" if "\r\n" in text else "\n")
    w.writerows([head] + kept)
    return buf.getvalue()


def main():
    ctx_path, raw, out = sys.argv[1:4]
    ctx = json.load(open(ctx_path))
    fingerprint = ""
    report_dir = os.path.join(raw, "report")
    rj = os.path.join(report_dir, "report.json")
    if os.path.exists(rj):
        fingerprint = json.load(open(rj)).get("upload", {}).get("server_fingerprint", "")
    replace = compile_replacer(placeholder_map(ctx), fingerprint)
    notes = []
    os.makedirs(out, exist_ok=True)

    p = os.path.join(raw, "terminal.txt")
    if os.path.exists(p):
        open(os.path.join(out, "terminal.txt"), "w").write(replace(open(p).read()))

    if os.path.isdir(report_dir):
        for name in sorted(n for n in os.listdir(report_dir) if n.endswith(".csv")):
            text = open(os.path.join(report_dir, name), newline="").read()
            if name == "ports.csv":
                text = trim_ports_csv(text, ctx, notes)
            open(os.path.join(out, name), "w", newline="").write(replace(text))

    if os.path.exists(rj):
        doc = json.load(open(rj))
        trim_report(doc, ctx, notes)
        text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
        open(os.path.join(out, "report.json"), "w").write(replace(text))
        notes.append("report.json: re-serialised after trimming (2-space indent, as the tool writes it; key order kept)")

    with open(os.path.join(out, "TRIMMED.md"), "w") as f:
        f.write("# What was trimmed from this run\n\n")
        f.write("Host-wide inventory unrelated to the scenario; see ../../README.md § Sanitisation.\n\n")
        for n in notes or ["nothing"]:
            f.write(f"- {n}\n")


if __name__ == "__main__":
    main()
