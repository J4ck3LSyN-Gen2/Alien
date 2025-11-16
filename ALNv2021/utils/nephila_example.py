import ALNv2021 as alien
import asyncio
import os
import json

# --- Configuration ---
# It's good practice to have a logger for visibility into the operations.
logger = alien.loggerHandle('nephila_example', configOverride={'enableConsoleLogging': True})
logger.setConsoleLevel('info') # Set to 'debug' for more verbose output

# A safe target provided by the nmap project for scanning practice.
TARGET_HOST = "scanme.nmap.org"
TARGET_DOMAIN = "nmap.org"

# --- Initialization ---
# Initialize the nephila utility.
# We can pass the logger's logPipe method to bridge nephila's internal logging.
logger.infoLog("main", "Initializing nephila utility...")
nephila_instance = alien.utils.nephila(logPipe=logger.logPipe)


def demonstrate_base_scanner():
    """
    Demonstrates using the baseScanner for various stealthy port scans.
    Note: These scans require root/administrator privileges.
    """
    print("\n" + "="*20 + " [Base Scanner Example] " + "="*20)
    if os.geteuid() != 0:
        logger.warningLog("demonstrate_base_scanner", "Base scanner requires root privileges. Skipping.")
        print("[-] Base scanner requires root privileges. Skipping this example.")
        return

    scanner = nephila_instance.baseScanner(nephila_instance, host=TARGET_HOST, timeout=1.5)

    ports_to_scan = [80, 22, 443, 8080]
    print(f"[*] Performing SYN scan on {TARGET_HOST} for ports: {ports_to_scan}")
    
    # SYN Scan (default)
    results = scanner._scanPorts(ports_to_scan, maxThreads=10)
    print(f"[+] SYN Scan Results: {results}")

    # FIN Scan
    print(f"\n[*] Performing FIN scan on {TARGET_HOST} for ports: {ports_to_scan}")
    scanner._setStealthFinFlag()
    results_fin = scanner._scanPorts(ports_to_scan, maxThreads=10)
    print(f"[+] FIN Scan Results: {results_fin}")


def demonstrate_nmap_scanner():
    """
    Demonstrates using the nmap wrapper for more advanced scans.
    """
    print("\n" + "="*20 + " [Nmap Scanner Example] " + "="*20)
    nmap_scanner = nephila_instance.nmap(nephila_instance)

    print(f"[*] Running nmap version scan on {TARGET_HOST} for ports 80, 443...")
    results = nmap_scanner.scan(
        targets=TARGET_HOST,
        ports="80,443",
        args="sV",  # Argument for service version detection
        verbose=True
    )
    print("[+] Nmap scan results:")
    # Using pformat for pretty printing the dictionary
    print(json.dumps(results, indent=2))


def demonstrate_enumeration():
    """
    Demonstrates DNS and domain enumeration capabilities.
    """
    print("\n" + "="*20 + " [Enumeration Example] " + "="*20)
    enumerator = nephila_instance.enumeration(nephila_instance)

    print(f"[*] Performing DNS 'A' record query for {TARGET_DOMAIN}...")
    a_records = enumerator.dnsQuery(TARGET_DOMAIN, "A")
    print(f"[+] 'A' Records: {a_records}")

    print(f"\n[*] Performing reverse DNS query for {a_records[0]}...")
    hostname = enumerator.dnsReverseQuery(a_records[0])
    print(f"[+] Reverse DNS: {hostname}")

    print(f"\n[*] Performing a full enumeration on {TARGET_DOMAIN}...")
    full_enum_data = enumerator.gatherEnumData(TARGET_DOMAIN)
    print("[+] Full Enumeration Results:")
    print(json.dumps(full_enum_data, indent=2))


def demonstrate_firewall_fragmentation():
    """
    Demonstrates the firewall fragmentation scan.
    Note: This scan requires root/administrator privileges.
    """
    print("\n" + "="*20 + " [Firewall Fragmentation Example] " + "="*20)
    if os.geteuid() != 0:
        logger.warningLog("demonstrate_firewall_fragmentation", "Firewall fragmentation requires root privileges. Skipping.")
        print("[-] Firewall fragmentation requires root privileges. Skipping this example.")
        return

    frag_scanner = nephila_instance.firewallFrag(nephila_instance)
    
    print(f"[*] Sending fragmented packets to {TARGET_HOST} on port 80...")
    try:
        result = frag_scanner.scan(
            rHost=TARGET_HOST,
            rPort=80,
            maxRandomDataLength=256, # Smaller payload for example
            verbose=True
        )
        print(f"[+] Fragmentation scan completed: {result}")
    except PermissionError as e:
        print(f"[!] {e}")


async def demonstrate_proxify():
    """
    Demonstrates fetching, verifying, and using proxies.
    This is an async function because many proxify methods are async.
    """
    print("\n" + "="*20 + " [Proxify Example] " + "="*20)
    proxy_manager = nephila_instance.proxify(nephila_instance)

    print("[*] Fetching and verifying 5 public HTTP proxies...")
    # Fetching a small number for the example. This can take a moment.
    verified_proxies = await proxy_manager.fetchAndVerify(limit=5, proxyType='http')
    
    if not verified_proxies:
        print("[!] Could not fetch any verified proxies. Skipping rest of example.")
        return

    print(f"[+] Fetched {len(verified_proxies)} verified proxies.")
    print(json.dumps(verified_proxies, indent=2, default=str))

    print("\n[*] Getting a random proxy from the verified list...")
    random_proxy = proxy_manager.getRandomProxy()
    print(f"[+] Random proxy: {random_proxy}")

    print("\n[*] Getting the best-scoring proxy...")
    best_proxy = proxy_manager.getProxy(strategy='best')
    if best_proxy:
        print(f"[+] Best proxy: {best_proxy['proxy']} (Score: {best_proxy['score']})")

    print("\n[*] Rotating through proxies...")
    for i in range(3):
        rotated_proxy = proxy_manager.rotateProxy()
        print(f"  - Rotation {i+1}: {rotated_proxy}")

    print("\n[*] Getting proxy statistics...")
    stats = proxy_manager.getProxyStats()
    print("[+] Stats:")
    print(json.dumps(stats, indent=2))


def demonstrate_mitm_capture():
    """
    Demonstrates setting up a simple MITM packet capture.
    Note: This requires root/administrator privileges.
    """
    print("\n" + "="*20 + " [MITM Capture Example] " + "="*20)
    if os.geteuid() != 0:
        logger.warningLog("demonstrate_mitm_capture", "MITM capture requires root privileges. Skipping.")
        print("[-] MITM capture requires root privileges. Skipping this example.")
        return

    mitm_handler = nephila_instance.mitmCapture(nephila_instance)

    print("[*] Starting packet capture for 10 seconds (filter: 'tcp port 80')...")
    print("[*] In another terminal, try running: curl http://example.com")

    capture_thread = alien.threading.Thread(
        target=mitm_handler.startCapture,
        kwargs={'packetFilter': "tcp port 80"},
        daemon=True
    )
    
    try:
        capture_thread.start()
        time.sleep(10) # Capture for 10 seconds
    finally:
        mitm_handler.stopCapture()
        capture_thread.join(timeout=2)

    print("\n[+] Capture stopped.")
    stats = mitm_handler.getCaptureStats()
    print("[+] Capture Statistics:")
    print(json.dumps(stats, indent=2))

    if stats['totalPackets'] > 0:
        export_path = "mitm_capture_example.json"
        print(f"\n[*] Exporting captured packet info to {export_path}...")
        mitm_handler.exportCapture(export_path)
        print(f"[+] Export complete.")


if __name__ == "__main__":
    # Check for root if needed by some examples
    is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False

    # --- Run Demonstrations ---
    demonstrate_nmap_scanner()
    demonstrate_enumeration()
    
    if is_root:
        demonstrate_base_scanner()
        demonstrate_firewall_fragmentation()
        # demonstrate_mitm_capture() # This is interactive, uncomment to run
    else:
        print("\n[!] Some examples require root/administrator privileges and will be skipped.")

    # Run async demonstration for proxify
    asyncio.run(demonstrate_proxify())

    print("\n[+] All examples finished.")