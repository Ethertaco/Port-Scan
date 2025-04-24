# Author: QinShenYu
# This code base has been modified using AI assistance.
import socket,ipaddress,argparse,sys,threading,time
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置 ---
PORT_TO_SCAN = 5126
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
        with print_lock:
            print(f"[!] 错误: 无法解析主机名/IP {ip}", file=sys.stderr)
        return False
    except socket.error as e:
        # with print_lock:
        #     print(f"[!] Socket 错误 {ip}:{port}: {e}", file=sys.stderr)
        return False
    finally:
        if sock:
            sock.close()

def get_target_ips(targets_string):
    target_ips = []
    targets_list = targets_string.split(',')
    for target in targets_list:
        target = target.strip()
        if not target:
            continue
        try:
            ip_obj = ipaddress.ip_network(target, strict=False)
            if ip_obj.num_addresses > 1:
                if ip_obj.prefixlen < 31:
                    target_ips.extend(list(ip_obj.hosts()))
                else:
                    target_ips.extend(list(ip_obj.network_address for _ in range(ip_obj.num_addresses)))
            else:
                # 是单个 IP
                target_ips.append(ip_obj.network_address)
        except ValueError:
            print(f"[!] 错误: 无效的 IP 地址或网络格式 '{target}'。", file=sys.stderr)
            return None # 指示错误
    return sorted(list(set(target_ips)))

def main():
    parser = argparse.ArgumentParser(description=f"一个简单的内网端口扫描器")
    parser.add_argument("targets", help="目标 IP 地址或 CIDR 网络，用逗号分隔(例如: 192.168.1.1,192.168.2.0/24)")
    parser.add_argument("-p", "--port", type=int, default=PORT_TO_SCAN,
                        help=f"指定端口(默认: {PORT_TO_SCAN})")
    parser.add_argument("-t", "--timeout", type=float, default=DEFAULT_TIMEOUT,
                        help=f"连接超时时间(秒) (默认: {DEFAULT_TIMEOUT})")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_THREADS,
                        help=f"并发扫描线程数(默认: {DEFAULT_THREADS})")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="显示关闭或超时的端口")
    
    args = parser.parse_args()

    # --- 输入验证 ---
    target_ips = get_target_ips(args.targets)
    if target_ips is None or not target_ips:
        print("[!] 未指定有效的目标。", file=sys.stderr)
        sys.exit(1)

    if args.timeout <= 0:
        print("[!] 错误: 超时时间必须为正数。", file=sys.stderr)
        sys.exit(1)

    if args.workers <= 0:
        print("[!] 错误: 工作线程数必须为正数。", file=sys.stderr)
        sys.exit(1)
    
    if args.port <= 0 or args.port >= 65536:
        print("[!] 错误: 端口必须为1-65535。", file=sys.stderr)
        sys.exit(1)

    # --- 准备扫描 ---
    total_tasks = len(target_ips)
    if args.port==None:
        args.port=PORT_TO_SCAN

    print("-" * 60)
    print(f"[*] 开始端口 {args.port} 扫描，时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] 目标: {args.targets} (共 {len(target_ips)} 个主机)")
    print(f"[*] 扫描端口: {args.port}")
    print(f"[*] 超时: {args.timeout}s | 线程数: {args.workers}")
    print(f"[*] 总扫描任务数: {total_tasks}")
    print("-" * 60)
    print()

    # --- 执行扫描 ---
    start_time = time.time()
    open_ports_found_count = 0
    tasks_completed = 0
    open_ports_list=[]

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures_map = {
            executor.submit(scan_single_port, ip, args.port, args.timeout): ip
            for ip in target_ips
        }

        for future in as_completed(futures_map):
            ip = futures_map[future]
            try:
                is_open = future.result()
                if is_open:
                    with print_lock:
                        print(f"[+] 开放: {ip}:{args.port}")
                    open_ports_found_count += 1
                    open_ports_list+=[str(ip)+":"+str(args.port)]
                elif args.verbose:
                     with print_lock:
                         print(f"[-] 关闭: {ip}:{args.port}")

            except Exception as e:
                 with print_lock:
                    print(f"[!] 处理 {ip}:{args.port} 的结果时出错: {e}", file=sys.stderr)
            finally:
                tasks_completed += 1
                if tasks_completed % (args.workers // 2 + 1) == 0 or tasks_completed == total_tasks:
                     elapsed = time.time() - start_time
                     progress = (tasks_completed / total_tasks) * 100
                     print(f"\r[*] 进度: {tasks_completed}/{total_tasks} ({progress:.1f}%) | 发现开放: {open_ports_found_count} | 已用时: {elapsed:.1f}s", end="", file=sys.stderr)
                     print("")


    # --- 结束 ---
    end_time = time.time()
    print("\n" + "-" * 60, file=sys.stderr)
    print(f"[*] 扫描完成，总耗时 {end_time - start_time:.2f} 秒")
    print(f"[*] 共发现 {open_ports_found_count} 个开放的 {args.port} 端口, 结果如下")
    for i in range(len(open_ports_list)):
        print(f"[*] {i+1}. {open_ports_list[i]}")
    print("-" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户中断扫描", file=sys.stderr)
        sys.exit(1)
