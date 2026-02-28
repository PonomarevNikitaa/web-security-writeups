import requests
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, init
from urllib.parse import urlparse

init(autoreset=True)

lock = threading.Lock()

def load_payloads(wordlist_path):
    try:
        with open(wordlist_path, 'r', encoding="utf-8") as file:
            return [
                line.strip()
                for line in file
                if line.strip() and not line.strip().startswith("#")
            ]
    except FileNotFoundError:
        print(Fore.RED + "[!] Wordlist not found.")
        sys.exit(1)


def build_proxies(proxy):
    if proxy:
        return {
            "http": proxy,
            "https": proxy
        }
    return None


def parse_headers(headers_list):
    headers = {}
    if headers_list:
        for header in headers_list:
            try:
                key, value = header.split(":", 1)
                headers[key.strip()] = value.strip()
            except ValueError:
                print(Fore.YELLOW + f"[!] Invalid header format: {header}")
    return headers


def send_request(method, url, headers=None, data=None, proxies=None):
    try:
        if method == "GET":
            return requests.get(url, headers=headers, proxies=proxies, timeout=5)
        elif method == "POST":
            return requests.post(url, headers=headers, data=data, proxies=proxies, timeout=5)
    except requests.RequestException:
        return None


def analyze_response(response, baseline_length):
    suspicious = False

    if response.status_code >= 500:
        suspicious = True

    if abs(len(response.text) - baseline_length) > 100:
        suspicious = True

    error_patterns = [
        "sql", "syntax", "exception",
        "warning", "mysql", "postgres",
        "stack trace", "fatal error"
    ]

    body_lower = response.text.lower()
    for pattern in error_patterns:
        if pattern in body_lower:
            suspicious = True

    return suspicious


def fuzz_payload(payload, args, baseline_length, headers, proxies, log_file):
    if args.method == "GET":
        target_url = args.url.replace("FUZZ", payload)
        response = send_request("GET", target_url, headers=headers, proxies=proxies)
    else:
        target_url = args.url
        data = args.data.replace("FUZZ", payload) if args.data else None
        response = send_request("POST", target_url, headers=headers, data=data, proxies=proxies)

    if not response:
        return

    suspicious = analyze_response(response, baseline_length)

    output = f"{payload} -> {response.status_code} | length={len(response.text)}"

    with lock:
        if suspicious:
            print(Fore.RED + "[!] " + output)
            if log_file:
                log_file.write("[SUSPICIOUS] " + output + "\n")
        else:
            print(Fore.GREEN + "[OK] " + output)
            if log_file:
                log_file.write("[OK] " + output + "\n")


def main():
    parser = argparse.ArgumentParser(description="Advanced HTTP Fuzzer")
    parser.add_argument("-u", "--url", required=True, help="Target URL (use FUZZ for GET)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to payload list")
    parser.add_argument("-m", "--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("-d", "--data", help="POST data (use FUZZ inside)")
    parser.add_argument("-t", "--threads", type=int, default=5)
    parser.add_argument("--proxy", help="Proxy (example: http://127.0.0.1:8080)")
    parser.add_argument("-H", "--header", action="append", help="Custom header (Key: Value)")
    parser.add_argument("-o", "--output", help="Log results to file")

    args = parser.parse_args()

    if args.method == "GET" and "FUZZ" not in args.url:
        print(Fore.RED + "[!] GET request must contain FUZZ in URL.")
        sys.exit(1)

    if args.method == "POST" and (not args.data or "FUZZ" not in args.data):
        print(Fore.RED + "[!] POST request must contain FUZZ in data.")
        sys.exit(1)

    payloads = load_payloads(args.wordlist)
proxies = build_proxies(args.proxy)
    headers = parse_headers(args.header)

    print(Fore.CYAN + "[*] Getting baseline response...")

    if args.method == "GET":
        baseline_response = send_request("GET", args.url.replace("FUZZ", "test"), headers=headers, proxies=proxies)
    else:
        baseline_response = send_request("POST", args.url, headers=headers, data=args.data.replace("FUZZ", "test"), proxies=proxies)

    if not baseline_response:
        print(Fore.RED + "[!] Could not get baseline response.")
        sys.exit(1)

    baseline_length = len(baseline_response.text)
    print(Fore.GREEN + f"[*] Baseline length: {baseline_length}")
    print(Fore.CYAN + "[*] Starting fuzzing...\n")

    log_file = open(args.output, "w") if args.output else None

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for payload in payloads:
            executor.submit(
                fuzz_payload,
                payload,
                args,
                baseline_length,
                headers,
                proxies,
                log_file
            )

    if log_file:
        log_file.close()

if name == "__main__":
    main()
