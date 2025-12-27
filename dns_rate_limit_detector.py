#!/usr/bin/env python3
import argparse
import json
import random
import select
import signal
import socket
import string
import sys
import threading
import time

ALPHABET = string.ascii_lowercase + string.digits
ID_LABEL_TEMPLATE = "id00000000"


def encode_qname(name):
    parts = name.rstrip(".").split(".")
    out = bytearray()
    for part in parts:
        if len(part) > 63:
            raise ValueError("label too long")
        out.append(len(part))
        out.extend(part.encode("ascii"))
    out.append(0)
    return bytes(out)


def decode_qname(msg, offset):
    labels = []
    jumped = False
    seen = set()
    start_offset = offset
    while True:
        if offset >= len(msg):
            raise ValueError("invalid qname")
        length = msg[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(msg):
                raise ValueError("invalid qname pointer")
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if pointer in seen:
                raise ValueError("qname pointer loop")
            seen.add(pointer)
            offset = pointer
            jumped = True
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        if offset + length > len(msg):
            raise ValueError("invalid qname label length")
        labels.append(msg[offset:offset + length].decode("ascii", "replace"))
        offset += length
    name = ".".join(labels)
    if jumped:
        return name, start_offset + 2
    return name, offset


def build_query(qname, qid):
    header = qid.to_bytes(2, "big") + b"\x01\x00" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    question = encode_qname(qname) + b"\x00\x10" + b"\x00\x01"
    return header + question


def parse_response(msg):
    if len(msg) < 12:
        return None, None
    qid = int.from_bytes(msg[0:2], "big")
    flags = int.from_bytes(msg[2:4], "big")
    rcode = flags & 0x000F
    return qid, rcode


def build_response(query, txt_value, rcode=0):
    if len(query) < 12:
        return None
    qid = query[0:2]
    flags_req = int.from_bytes(query[2:4], "big")
    rd = flags_req & 0x0100
    flags = 0x8000 | 0x0400 | rd | (rcode & 0x000F)
    qdcount = query[4:6]
    if qdcount != b"\x00\x01":
        return None
    try:
        _, qend = decode_qname(query, 12)
    except ValueError:
        return None
    if qend + 4 > len(query):
        return None
    question = query[12:qend + 4]
    header = qid + flags.to_bytes(2, "big") + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00"
    txt_bytes = txt_value.encode("ascii", "replace")
    if len(txt_bytes) > 255:
        txt_bytes = txt_bytes[:255]
    rdata = bytes([len(txt_bytes)]) + txt_bytes
    answer = b"\xC0\x0C" + b"\x00\x10" + b"\x00\x01" + b"\x00\x00\x00\x1E" + len(rdata).to_bytes(2, "big") + rdata
    return header + question + answer


def random_label(length):
    return "".join(random.choice(ALPHABET) for _ in range(length))


def generate_name(domain, min_len, max_len):
    target_len = random.randint(min_len, max_len)
    domain = domain.rstrip(".")
    base_len = len(domain) + 1
    if base_len >= target_len:
        raise ValueError("domain too long for requested name length")
    sub_len = target_len - base_len
    labels = []
    remaining = sub_len
    while remaining > 0:
        if remaining <= 63:
            labels.append(random_label(remaining))
            remaining = 0
        else:
            max_label = min(63, remaining - 2)
            label_len = random.randint(1, max_label)
            labels.append(random_label(label_len))
            remaining -= label_len + 1
    return ".".join(labels) + "." + domain


def generate_subdomain_with_length(total_len):
    labels = []
    remaining = total_len
    while remaining > 0:
        if remaining <= 63:
            labels.append(random_label(remaining))
            remaining = 0
        else:
            max_label = min(63, remaining - 2)
            label_len = random.randint(1, max_label)
            labels.append(random_label(label_len))
            remaining -= label_len + 1
    return ".".join(labels)


def generate_name_with_id(domain, min_len, max_len, id_label):
    domain = domain.rstrip(".")
    base_len = len(domain) + 1 + len(id_label)
    min_len = max(min_len, base_len)
    if min_len > max_len:
        raise ValueError("domain too long for requested name length")
    while True:
        target_len = random.randint(min_len, max_len)
        if target_len == base_len + 1:
            continue
        break
    if target_len == base_len:
        return f"{id_label}.{domain}"
    random_len = target_len - base_len - 1
    random_sub = generate_subdomain_with_length(random_len)
    return f"{id_label}.{random_sub}.{domain}"


def compute_latency_stats(rtts_ms):
    if not rtts_ms:
        return {}
    sorted_rtts = sorted(rtts_ms)

    def percentile(pct):
        if len(sorted_rtts) == 1:
            return sorted_rtts[0]
        k = (len(sorted_rtts) - 1) * pct
        f = int(k)
        c = min(f + 1, len(sorted_rtts) - 1)
        if f == c:
            return sorted_rtts[f]
        d = k - f
        return sorted_rtts[f] + (sorted_rtts[c] - sorted_rtts[f]) * d

    avg = sum(sorted_rtts) / float(len(sorted_rtts))
    return {
        "min_ms": round(sorted_rtts[0], 3),
        "avg_ms": round(avg, 3),
        "p50_ms": round(percentile(0.50), 3),
        "p95_ms": round(percentile(0.95), 3),
        "p99_ms": round(percentile(0.99), 3),
        "max_ms": round(sorted_rtts[-1], 3),
    }


def generate_subdomain_with_length(total_len):
    labels = []
    remaining = total_len
    while remaining > 0:
        if remaining <= 63:
            labels.append(random_label(remaining))
            remaining = 0
        else:
            max_label = min(63, remaining - 2)
            label_len = random.randint(1, max_label)
            labels.append(random_label(label_len))
            remaining -= label_len + 1
    return ".".join(labels)


def generate_name_with_id(domain, min_len, max_len, id_label):
    domain = domain.rstrip(".")
    base_len = len(domain) + 1 + len(id_label)
    min_len = max(min_len, base_len)
    if min_len > max_len:
        raise ValueError("domain too long for requested name length")
    while True:
        target_len = random.randint(min_len, max_len)
        if target_len == base_len + 1:
            continue
        break
    if target_len == base_len:
        return f"{id_label}.{domain}"
    random_len = target_len - base_len - 1
    random_sub = generate_subdomain_with_length(random_len)
    return f"{id_label}.{random_sub}.{domain}"


def compute_latency_stats(rtts_ms):
    if not rtts_ms:
        return {}
    sorted_rtts = sorted(rtts_ms)

    def percentile(pct):
        if len(sorted_rtts) == 1:
            return sorted_rtts[0]
        k = (len(sorted_rtts) - 1) * pct
        f = int(k)
        c = min(f + 1, len(sorted_rtts) - 1)
        if f == c:
            return sorted_rtts[f]
        d = k - f
        return sorted_rtts[f] + (sorted_rtts[c] - sorted_rtts[f]) * d

    avg = sum(sorted_rtts) / float(len(sorted_rtts))
    return {
        "min_ms": round(sorted_rtts[0], 3),
        "avg_ms": round(avg, 3),
        "p50_ms": round(percentile(0.50), 3),
        "p95_ms": round(percentile(0.95), 3),
        "p99_ms": round(percentile(0.99), 3),
        "max_ms": round(sorted_rtts[-1], 3),
    }


class DNSServer(threading.Thread):
    def __init__(self, bind_ip, bind_port, domain, txt_value):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.domain = domain.rstrip(".")
        self.txt_value = txt_value
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.bind_ip, self.bind_port))
        self.running = True
        self.query_count = 0

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except OSError:
                break
            if not data:
                continue
            try:
                qname, qend = decode_qname(data, 12)
            except ValueError:
                continue
            if qend + 4 > len(data):
                continue
            qtype = int.from_bytes(data[qend:qend + 2], "big")
            if not qname.endswith(self.domain):
                resp = build_response(data, self.txt_value, rcode=3)
            elif qtype != 16:
                resp = build_response(data, self.txt_value, rcode=0)
            else:
                resp = build_response(data, self.txt_value, rcode=0)
                self.query_count += 1
            if resp:
                try:
                    self.sock.sendto(resp, addr)
                except OSError:
                    continue

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def parse_args():
    parser = argparse.ArgumentParser(description="Probe public resolver DNS rate limits using unique TXT queries.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    probe = subparsers.add_parser("probe", help="Run a rate-limit probe against a resolver.")
    probe.add_argument("domain", nargs="?", help="Domain name (authoritative zone) to query.")
    probe.add_argument("soa_ip", nargs="?", help="IP address of the SOA (bind address for the mini DNS server).")
    probe.add_argument("resolver_ip", nargs="?", help="Target public resolver IP address.")
    probe.add_argument("--resolver-port", type=int, default=None, help="Target resolver port (default: 53).")
    probe.add_argument("--listen-port", type=int, default=None, help="UDP port for the mini DNS server (default: 53).")
    probe.add_argument("--start-qps", type=int, default=None, help="Starting QPS (default: 10).")
    probe.add_argument("--step-qps", type=int, default=None, help="QPS increment per window (default: 10).")
    probe.add_argument("--max-qps", type=int, default=None, help="Maximum QPS to attempt (default: 1000).")
    probe.add_argument("--window-seconds", type=float, default=None, help="Duration of each QPS window (default: 5s).")
    probe.add_argument("--grace-seconds", type=float, default=None, help="Extra time to collect late responses (default: 1s).")
    probe.add_argument("--min-success-rate", type=float, default=None, help="Success ratio threshold (default: 0.95).")
    probe.add_argument("--consecutive-fail-windows", type=int, default=None, help="Windows below threshold before stopping (default: 3).")
    probe.add_argument("--min-name-len", type=int, default=None, help="Minimum FQDN length for TXT queries.")
    probe.add_argument("--max-name-len", type=int, default=None, help="Maximum FQDN length for TXT queries.")
    probe.add_argument("--max-runtime", type=float, default=None, help="Maximum runtime in seconds (default: 300).")
    probe.add_argument("--txt-value", default=None, help="TXT response value (default: ok).")
    probe.add_argument("--config", help="Path to JSON config file (default: config/config.json).")
    probe.add_argument("--out", required=True, help="Path to write JSON results.")

    report = subparsers.add_parser("report", help="Generate a comparison report from result files.")
    report.add_argument("results", nargs="+", help="One or more JSON result files.")
    report.add_argument("--out", help="Write report to file instead of stdout.")
    return parser.parse_args()


def write_report(result_files, out_path=None):
    rows = []
    for path in result_files:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        summary = data.get("summary", {})
        config = data.get("config", {})
        rows.append({
            "file": path,
            "resolver_ip": config.get("resolver_ip"),
            "resolver_port": config.get("resolver_port"),
            "domain": config.get("domain"),
            "soa_ip": config.get("soa_ip"),
            "last_good_qps": summary.get("last_good_qps"),
            "elapsed_seconds": summary.get("elapsed_seconds"),
            "stopped_due_to_rate_limit": summary.get("stopped_due_to_rate_limit"),
            "windows": len(data.get("windows", [])),
            "rtt_avg_ms": data.get("overall_rtt_stats", {}).get("avg_ms"),
            "rtt_p95_ms": data.get("overall_rtt_stats", {}).get("p95_ms"),
        })

    header = [
        "file",
        "resolver_ip",
        "resolver_port",
        "domain",
        "soa_ip",
        "last_good_qps",
        "elapsed_seconds",
        "stopped_due_to_rate_limit",
        "windows",
        "rtt_avg_ms",
        "rtt_p95_ms",
    ]
    lines = [",".join(header)]
    for row in rows:
        line = ",".join(str(row.get(col, "")) for col in header)
        lines.append(line)
    output = "\n".join(lines)

    if out_path:
        with open(out_path, "w", encoding="utf-8") as handle:
            handle.write(output + "\n")
    else:
        print(output)


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    return data


def main():
    args = parse_args()
    if args.command == "report":
        write_report(args.results, args.out)
        return 0

    config_path = args.config or "config/config.json"
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        config = None
    if config:
        for key, value in config.items():
            if hasattr(args, key) and getattr(args, key) is None:
                setattr(args, key, value)

    defaults = {
        "resolver_port": 53,
        "listen_port": 53,
        "start_qps": 10,
        "step_qps": 10,
        "max_qps": 1000,
        "window_seconds": 5.0,
        "grace_seconds": 1.0,
        "min_success_rate": 0.95,
        "consecutive_fail_windows": 3,
        "min_name_len": 150,
        "max_name_len": 200,
        "max_runtime": 300.0,
        "txt_value": "ok",
    }
    for key, value in defaults.items():
        if getattr(args, key) is None:
            setattr(args, key, value)

    if not args.domain or not args.soa_ip or not args.resolver_ip:
        print("domain, soa_ip, and resolver_ip are required (via args or config).", file=sys.stderr)
        return 1

    domain = args.domain.rstrip(".")
    if args.min_name_len > args.max_name_len:
        print("min-name-len must be <= max-name-len", file=sys.stderr)
        return 1
    min_required = len(domain) + 1 + len(ID_LABEL_TEMPLATE)
    if args.min_name_len < min_required:
        print("min-name-len too small for domain and id label length", file=sys.stderr)
        return 1

    server = DNSServer(args.soa_ip, args.listen_port, domain, args.txt_value)
    try:
        server.start()
    except OSError as exc:
        print(f"failed to start DNS server: {exc}", file=sys.stderr)
        return 1

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.setblocking(False)

    stop = False

    def handle_sigint(_signum, _frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, handle_sigint)

    qps = args.start_qps
    max_runtime = args.max_runtime
    started_at = time.monotonic()
    consecutive_bad = 0
    last_good_qps = 0
    window_index = 0

    print("starting probe...")
    print("window,qps,achieved_qps,sent,responses,success_rate,rtt_avg_ms,rtt_p95_ms,rcode_counts")
    results = []
    all_rtts_ms = []
    request_counter = 0

    while not stop:
        now = time.monotonic()
        if now - started_at >= max_runtime:
            break
        if qps <= 0 or qps > args.max_qps:
            break

        sent = 0
        responses = 0
        rcode_counts = {}
        outstanding = {}
        rtts_ms = []

        window_start = time.monotonic()
        window_end = window_start + args.window_seconds
        send_interval = 1.0 / float(qps)
        next_send = window_start

        while time.monotonic() < window_end and not stop:
            now = time.monotonic()
            timeout = max(0.0, next_send - now)
            rlist, _, _ = select.select([client_sock], [], [], timeout)
            if rlist:
                data, _ = client_sock.recvfrom(2048)
                qid, rcode = parse_response(data)
                if qid in outstanding:
                    rtt_ms = (time.monotonic() - outstanding[qid]) * 1000.0
                    rtts_ms.append(rtt_ms)
                    responses += 1
                    rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
                    del outstanding[qid]
            now = time.monotonic()
            while now >= next_send:
                req_id = f"id{request_counter:08x}"
                request_counter += 1
                qname = generate_name_with_id(domain, args.min_name_len, args.max_name_len, req_id)
                while True:
                    qid = random.randint(0, 65535)
                    if qid not in outstanding:
                        break
                packet = build_query(qname, qid)
                try:
                    client_sock.sendto(packet, (args.resolver_ip, args.resolver_port))
                except OSError:
                    pass
                outstanding[qid] = time.monotonic()
                sent += 1
                next_send += send_interval
                now = time.monotonic()

        grace_end = time.monotonic() + args.grace_seconds
        while time.monotonic() < grace_end and not stop:
            timeout = max(0.0, grace_end - time.monotonic())
            rlist, _, _ = select.select([client_sock], [], [], timeout)
            if rlist:
                data, _ = client_sock.recvfrom(2048)
                qid, rcode = parse_response(data)
                if qid in outstanding:
                    rtt_ms = (time.monotonic() - outstanding[qid]) * 1000.0
                    rtts_ms.append(rtt_ms)
                    responses += 1
                    rcode_counts[rcode] = rcode_counts.get(rcode, 0) + 1
                    del outstanding[qid]

        window_duration = args.window_seconds
        achieved_qps = (sent / window_duration) if window_duration > 0 else 0.0
        success_rate = (responses / sent) if sent else 0.0
        rtt_stats = compute_latency_stats(rtts_ms)
        rtt_avg = rtt_stats.get("avg_ms", 0.0)
        rtt_p95 = rtt_stats.get("p95_ms", 0.0)
        all_rtts_ms.extend(rtts_ms)
        if success_rate >= args.min_success_rate:
            last_good_qps = qps
            consecutive_bad = 0
        else:
            consecutive_bad += 1

        print(f"{window_index},{qps},{achieved_qps:.3f},{sent},{responses},{success_rate:.3f},{rtt_avg:.3f},{rtt_p95:.3f},{rcode_counts}")
        results.append({
            "window": window_index,
            "qps": qps,
            "achieved_qps": round(achieved_qps, 6),
            "sent": sent,
            "responses": responses,
            "success_rate": round(success_rate, 6),
            "rcode_counts": rcode_counts,
            "rtt_ms": [round(value, 3) for value in rtts_ms],
            "rtt_stats": rtt_stats,
        })
        window_index += 1

        if consecutive_bad >= args.consecutive_fail_windows:
            break

        qps += args.step_qps

    server.stop()
    client_sock.close()

    elapsed = time.monotonic() - started_at
    limit_reached = consecutive_bad >= args.consecutive_fail_windows
    summary = {
        "elapsed_seconds": round(elapsed, 3),
        "last_good_qps": last_good_qps,
        "stopped_due_to_rate_limit": limit_reached,
        "server_queries_observed": server.query_count,
    }
    overall_rtt_stats = compute_latency_stats(all_rtts_ms)

    output = {
        "config": {
            "domain": domain,
            "soa_ip": args.soa_ip,
            "resolver_ip": args.resolver_ip,
            "resolver_port": args.resolver_port,
            "listen_port": args.listen_port,
            "start_qps": args.start_qps,
            "step_qps": args.step_qps,
            "max_qps": args.max_qps,
            "window_seconds": args.window_seconds,
            "grace_seconds": args.grace_seconds,
            "min_success_rate": args.min_success_rate,
            "consecutive_fail_windows": args.consecutive_fail_windows,
            "min_name_len": args.min_name_len,
            "max_name_len": args.max_name_len,
            "max_runtime": args.max_runtime,
            "txt_value": args.txt_value,
        },
        "summary": summary,
        "overall_rtt_stats": overall_rtt_stats,
        "windows": results,
    }

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(output, handle, indent=2, sort_keys=True)

    print("")
    print("summary")
    print(f"elapsed_seconds: {summary['elapsed_seconds']}")
    print(f"last_good_qps: {summary['last_good_qps']}")
    print(f"stopped_due_to_rate_limit: {summary['stopped_due_to_rate_limit']}")
    print(f"server_queries_observed: {summary['server_queries_observed']}")
    if overall_rtt_stats:
        print(f"rtt_avg_ms: {overall_rtt_stats.get('avg_ms')}")
        print(f"rtt_p95_ms: {overall_rtt_stats.get('p95_ms')}")
    print(f"results_written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
