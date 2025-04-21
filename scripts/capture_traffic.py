import subprocess
import os
import re

def get_interfaces():
    try:
        result = subprocess.run(["tshark", "-D"], capture_output=True, text=True, check=True)
        interfaces = []
        for line in result.stdout.splitlines():
            if match := re.match(r"(\d+)\.\s+(.+?)(\s+\(.+?\))?$", line):
                interfaces.append((match.group(1), match.group(2)))
        return interfaces
    except Exception as e:
        print(f"Error listing interfaces: {str(e)}")
        return []

def capture_traffic(output_file, duration=5):
    output_file = os.path.abspath(output_file)
    
    interfaces = get_interfaces()
    if not interfaces:
        print("No interfaces found. Ensure Tshark is installed.")
        return False
    
    print(f"Available interfaces: {[(idx, name) for idx, name in interfaces]}")
    
    output_dir = os.path.dirname(output_file)
    try:
        os.makedirs(output_dir, exist_ok=True)
        print(f"Output directory ready: {output_dir}")
    except Exception as e:
        print(f"Failed to create directory: {str(e)}")
        return False
    
    test_file = os.path.join(output_dir, "test_write.txt")
    try:
        with open(test_file, "w") as f:
            f.write("test")
        os.remove(test_file)
        print("Write access confirmed.")
    except Exception as e:
        print(f"No write access to {output_dir}: {str(e)}")
        return False
    
    # Tshark command
    cmd_base = [
        "tshark",
        "-T", "fields",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ip.len",
        "-e", "ip.proto",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-E", "separator=,",
        "-E", "header=y",
        "-a", f"duration:{duration}"
    ]
    
    success = False
    default_interfaces = [i for i in interfaces if 'wi-fi' in i[1].lower() or 'ethernet' in i[1].lower() or 'wlan' in i[1].lower()]
    trial_interfaces = default_interfaces + [i for i in interfaces if i not in default_interfaces]
    
    for interface_idx, interface_name in trial_interfaces:
        print(f"Trying interface {interface_idx}: {interface_name}")
        cmd = cmd_base.copy()
        cmd[1:1] = ["-i", interface_idx]
        
        try:
            count_cmd = cmd + ["-c", "100"]
            process = subprocess.run(
                count_cmd, capture_output=True, text=True, check=False
            )
            packet_count = len([line for line in process.stdout.splitlines() if line.strip() and not line.startswith("ip.src")])
            print(f"Interface {interface_idx} packets: {packet_count}")
            print("Sample stdout:", process.stdout[:2000] or "No stdout")
            print("Stderr:", process.stderr or "No stderr")
            
            if packet_count > 0:
                print(f"Writing to {output_file}...")
                with open(output_file, "w", newline='') as f:
                    process = subprocess.run(
                        cmd, stdout=f, stderr=subprocess.PIPE, text=True, check=True
                    )
                size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
                print(f"File size: {size} bytes")
                if size > 100:
                    success = True
                    break
                else:
                    print("Warning: File is empty or too small.")
            else:
                print(f"No packets on interface {interface_idx}. Trying next.")
        except subprocess.CalledProcessError as e:
            print(f"Tshark error on interface {interface_idx}: {e.stderr}")
        except Exception as e:
            print(f"Error on interface {interface_idx}: {str(e)}")
    
    if not success:
        print("Trying promiscuous mode on default interfaces...")
        for interface_idx, interface_name in default_interfaces:
            print(f"Trying promiscuous on {interface_idx}: {interface_name}")
            cmd = cmd_base.copy()
            cmd[1:1] = ["-i", interface_idx, "-p"]
            try:
                count_cmd = cmd + ["-c", "100"]
                process = subprocess.run(
                    count_cmd, capture_output=True, text=True, check=False
                )
                packet_count = len([line for line in process.stdout.splitlines() if line.strip() and not line.startswith("ip.src")])
                print(f"Promiscuous interface {interface_idx} packets: {packet_count}")
                print("Sample stdout:", process.stdout[:2000] or "No stdout")
                print("Stderr:", process.stderr or "No stderr")
                
                if packet_count > 0:
                    print(f"Writing to {output_file}...")
                    with open(output_file, "w", newline='') as f:
                        process = subprocess.run(
                            cmd, stdout=f, stderr=subprocess.PIPE, text=True, check=True
                        )
                    size = os.path.getsize(output_file) if os.path.exists(output_file) else 0
                    print(f"File size: {size} bytes")
                    if size > 100:
                        success = True
                        break
                    else:
                        print("Warning: File is empty or too small.")
                else:
                    print(f"No packets in promiscuous mode on {interface_idx}.")
            except subprocess.CalledProcessError as e:
                print(f"Tshark promiscuous error on {interface_idx}: {e.stderr}")
            except Exception as e:
                print(f"Error in promiscuous mode on {interface_idx}: {str(e)}")
    
    if success:
        print(f"Capture succeeded on {output_file}")
        return True
    else:
        print("Capture failed on all interfaces.")
        return False

if __name__ == "__main__":
    output_file = r"data\raw\live_traffic.csv"
    print("Starting capture...")
    success = capture_traffic(output_file, duration=5)
    if success:
        print("Capture completed successfully.")
    else:
        print("Capture failed. See errors above.")