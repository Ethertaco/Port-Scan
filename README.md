# Port Scan
Warn: This code base has been modified using *AI* assistance.
## What is Port Scan?
Port Scan is a port scanner program just like nmap, but it only has the most basic port detection function.(Hey, don't be so serious, this is just a project I'm using to practice :P)
## How to install?
### Windows
> Download the **`Port Scan.exe`** at Release or Main Branch
> 
> Open your cmd or powershell on the same directory
> 
> Done
### Linux
> Download the **`port_scan`** at Release or Main Branch
> 
> Open your terminal and type chmod command
>
> ```Terminal
> chmod +x port_scan
> ```
> Done
## How to use?
### Windows
You can type `"Port Scan.exe" -h` to check help menu
### Linux
You can type `./port_scan -h` to check help menu
 
When you typed -h, you can see some output on your terminal
```Terminal
usage: Port Scan.exe [-h] [-p PORT] [-t TIMEOUT] [-w WORKERS] [-v] targets

A simple intranet port scanner

positional arguments:

targets Target IP address or CIDR network, separated by commas (e.g.: 192.168.1.1,192.168.2.0/24)

options:

-h, --help show this help message and exit

-p PORT, --port PORT Specify the port (default: 5126)

-t TIMEOUT, --timeout TIMEOUT

Connection timeout (seconds) (default: 0.5)

-w WORKERS, --workers WORKERS

Number of concurrent scanning threads (default: 100)

-v, --verbose Show closed or timed-out ports
