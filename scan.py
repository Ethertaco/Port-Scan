# Author: QinShenYu
import socket, ipaddress, argparse, sys, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = 5126
DEFAULT_TIMEOUT = 0.5
DEFAULT_THREADS = 100

print_lock = threading.Lock()

def scan_single_port(ip, port, timeout):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        if result == 0:
            return True
        else:
            return False
    except socket.timeout:
        return False
    except socket.gaierror:
        return False
    except socket.error as e:
        return False
    finally:
        if sock:
            sock.close()

def get_target_ips(targets_string):
    target_ips = set()
    targets_list = targets_string.split(',')
    for target in targets_list:
        target = target.strip()
        if not target:
            continue
        try:
            ip_obj = ipaddress.ip_network(target, strict=False)
            for ip in ip_obj.hosts() if ip_obj.num_addresses > 1 else [ip_obj.network_address]:
                 target_ips.add(ip)
        except ValueError:
            with print_lock:
                print(f"[!] 错误: 无效的 IP 地址或网络格式 '{target}'", file=sys.stderr)
            return None
    return sorted(list(target_ips))

def parse_port_list(port_string):
    ports_to_scan = set()
    if not port_string:
        with print_lock:
            print("[!] 错误: 端口列表字符串不能为空", file=sys.stderr)
        return None

    port_parts = port_string.split(',')
    for part in port_parts:
        part = part.strip()
        if not part:
            continue
        try:
            port = int(part)
            if 1 <= port <= 65535:
                ports_to_scan.add(port)
            else:
                with print_lock:
                    print(f"[!] 错误: 端口号 '{part}' 无效 (必须在 1-65535 之间)", file=sys.stderr)
                return None
        except ValueError:
            with print_lock:
                print(f"[!] 错误: 无效的端口号 '{part}'", file=sys.stderr)
            return None

    if not ports_to_scan:
         with print_lock:
             print("[!] 错误: 未指定有效的端口", file=sys.stderr)
         return None

    return sorted(list(ports_to_scan))


def main():
    parser = argparse.ArgumentParser(description="一个简单的内网端口扫描器 (支持单端口或多端口)")
    parser.add_argument("targets", help="目标 IP 地址或 CIDR 网络，用逗号分隔 (例如: 192.168.1.1,192.168.2.0/24)")

    port_group = parser.add_mutually_exclusive_group(required=False)
    port_group.add_argument("-p", "--port", type=int,
                           help="指定要扫描的单个端口")
    port_group.add_argument("-pl", "--portlist",
                           help="指定要扫描的端口列表，用逗号分隔 (例如: 80,443,22)")

    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"连接超时时间(秒) (默认: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_THREADS,
                        help=f"并发扫描线程数(默认: {DEFAULT_THREADS})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="显示关闭或超时的端口")

    args = parser.parse_args()

    target_ips = get_target_ips(args.targets)
    if target_ips is None or not target_ips:
        if not target_ips:
             print("[!] 未指定有效的目标", file=sys.stderr)
        sys.exit(1)

    ports_to_scan = []
    ports_display_str = ""
    if args.port is not None:
        if not (1 <= args.port <= 65535):
            print(f"[!] 错误: 端口号 '{args.port}' 无效 (必须在 1-65535 之间)", file=sys.stderr)
            sys.exit(1)
        ports_to_scan = [args.port]
        ports_display_str = str(args.port)
    elif args.portlist is not None:
        ports_to_scan = parse_port_list(args.portlist)
        if ports_to_scan is None:
            sys.exit(1)
        ports_display_str = ",".join(map(str, ports_to_scan))
    else:
        ports_to_scan = [DEFAULT_PORTS]
        ports_display_str = str(DEFAULT_PORTS)


    if args.timeout <= 0:
        print("[!] 错误: 超时时间必须为正数", file=sys.stderr)
        sys.exit(1)

    if args.workers <= 0:
        print("[!] 错误: 工作线程数必须为正数", file=sys.stderr)
        sys.exit(1)

    total_tasks = len(target_ips) * len(ports_to_scan)

    print("-" * 60)
    print(f"[*] 开始端口扫描，时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] 目标: {args.targets} (共 {len(target_ips)} 个主机)")
    print(f"[*] 扫描端口: {ports_display_str} (共 {len(ports_to_scan)} 个端口)")
    print(f"[*] 超时: {args.timeout}s | 线程数: {args.workers}")
    print(f"[*] 总扫描任务数: {total_tasks}")
    print("-" * 60)
    print()

    start_time = time.time()
    open_ports_found_count = 0
    tasks_completed = 0
    open_ports_list = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures_map = {}
        for ip in target_ips:
            for port in ports_to_scan:
                future = executor.submit(scan_single_port, ip, port, args.timeout)
                futures_map[future] = (ip, port)

        for future in as_completed(futures_map):
            ip, port = futures_map[future]
            try:
                is_open = future.result()
                if is_open:
                    result_str = f"{ip}:{port}"
                    with print_lock:
                        print(f"[+] 开放: {result_str}")
                    open_ports_found_count += 1
                    open_ports_list.append(result_str)
                elif args.verbose:
                     with print_lock:
                         print(f"[-] 关闭/超时: {ip}:{port}")

            except Exception as e:
                 with print_lock:
                    print(f"[!] 处理 {ip}:{port} 的结果时出错: {e}", file=sys.stderr)
            finally:
                tasks_completed += 1
                if tasks_completed % (args.workers // 2 + 1) == 0 or tasks_completed == total_tasks:
                     elapsed = time.time() - start_time
                     progress = (tasks_completed / total_tasks) * 100 if total_tasks > 0 else 0
                     print(f"\r[*] 进度: {tasks_completed}/{total_tasks} ({progress:.1f}%) | 发现开放: {open_ports_found_count} | 已用时: {elapsed:.1f}s", end="", file=sys.stderr)
                     if tasks_completed == total_tasks:
                         print(file=sys.stderr)


    end_time = time.time()
    print(file=sys.stderr)
    print("-" * 60)
    print(f"[*] 扫描完成，总耗时 {end_time - start_time:.2f} 秒")
    if open_ports_found_count == 0:
        print(f"[*] 目标主机的端口没有开启")
    else:
        print(f"[*] 共发现 {open_ports_found_count} 个开放的端口, 结果如下:")
        open_ports_list.sort(key=lambda x: (ipaddress.ip_address(x.split(':')[0]), int(x.split(':')[1])))
        for i, open_port_info in enumerate(open_ports_list):
            print(f"[*] {i+1}. {open_port_info}")
    print("-" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断扫描", file=sys.stderr)
        sys.exit(1)