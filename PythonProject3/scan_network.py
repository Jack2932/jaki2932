import nmap
import sys

def scan_network(target_ip, ports="1-1024"):


    nm = nmap.PortScanner()

    try:
        nm.scan(target_ip, ports)

        for host in nm.all_hosts():
            print(f"Host: {host}")
            if 'tcp' in nm[host]:
                for port in nm[host]['tcp'].keys():
                    state = nm[host]['tcp'][port]['state']
                    name = nm[host]['tcp'][port]['name']
                    print(f"  Port: {port}  State: {state}  Service: {name}")
            else:
                print("  No open TCP ports found.")

    except nmap.PortScannerError as e:
        print(f"Ошибка при сканировании: {e}")
    except Exception as e:
        print(f"Произошла общая ошибка: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python scan_network.py <целевой_IP-адрес>")
        sys.exit(1)

    target_ip = sys.argv[1]
    print(f"Начинаем сканирование {target_ip}...")
    scan_network(target_ip)
    print("Сканирование завершено.")