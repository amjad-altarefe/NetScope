import pyshark
import shutil
import subprocess
from rich.table import Table
from rich.console import Console
import os

console = Console()

tshark_path = shutil.which("tshark")
TCP = '6'
UDP = "17"
ICMP = "1" 

OUTPUT_FILE = "captured_packets.pcapng"
global_table = None

def choose_interface():
    result = subprocess.run(
        [tshark_path, "-D"],
        text=True,
        capture_output=True
    ).stdout.strip()

    interfaces = [line.split()[1] for line in result.splitlines()]

    console.print("[bold cyan]=[/bold cyan]" * 70)
    console.print(result)
    console.print("[bold cyan]=[/bold cyan]" * 70)

    i = int(input("Which interface would you like to listen on: "))
    return interfaces[i - 1]

def choose_filter():
    print("Choose capture filter:")
    print("1 - TCP")
    print("2 - UDP")
    print("3 - ICMP")
    print("4 - All packets")

    choice = input("Enter choice: ").strip()

    return {
        "1": "tcp",
        "2": "udp",
        "3": "icmp"
    }.get(choice, None)

def clean_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def capture_packets(interface, packet_filter):
    global global_table

    capture = pyshark.LiveCapture(
        interface = interface,
        output_file = OUTPUT_FILE,
        tshark_path = tshark_path,
        bpf_filter = packet_filter
    )

    table = Table(title="Live Packet Capture (updating...)")
    table.add_column("SEQ#", style="bold cyan")
    table.add_column("Source IP", style="green")
    table.add_column("Source Port", style="yellow")
    table.add_column("Source MAC", style="magenta")
    table.add_column("Destination IP", style="green")
    table.add_column("Destination Port", style="yellow")
    table.add_column("Destination MAC", style="magenta")
    table.add_column("Protocol", style="red")

    seq = 1
    try:
        for pkt in capture.sniff_continuously(packet_count = 50):
            src_ip = pkt.ip.src if hasattr(pkt, "ip") else "N/A"
            dst_ip = pkt.ip.dst if hasattr(pkt, "ip") else "N/A"

            src_mac = pkt.eth.src if hasattr(pkt, "eth") else "N/A"
            dst_mac = pkt.eth.dst if hasattr(pkt, "eth") else "N/A"
            
            if hasattr(pkt, 'ip') :
                layer = ''
                if pkt.ip.proto == TCP:
                    layer = "TCP"
                elif pkt.ip.proto == UDP:
                    layer = "UDP"
                elif pkt.ip.proto == ICMP:
                    layer = "ICMP"
                else: 
                    layer = ''

            Hprotocol = pkt.highest_layer
            protocol = layer + "/" + Hprotocol
            
            src_port = dst_port = src_port = dst_port = "N/A"

            if hasattr(pkt, "tcp"):
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            elif hasattr(pkt, "udp"):
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport

            table.add_row(
                str(seq),
                src_ip,
                str(src_port),
                src_mac,
                dst_ip,
                str(dst_port),
                dst_mac,
                protocol
            )

            console.clear()
            console.print(table)
            seq += 1

    except KeyboardInterrupt:
        console.print("[bold red]Capture stopped by user[/bold red]")

    finally:
        capture.close()
        global_table = table
        console.print(f"[bold green]Saved to {OUTPUT_FILE}[/bold green]")

def show_packet_details():

    capture = pyshark.FileCapture(OUTPUT_FILE, tshark_path=tshark_path)

    while True:
        clean_screen()
        console.print(global_table)
        console.print("[bold cyan]-[/bold cyan]" * 100)

        try:
            seq = int(input("Enter packet SEQ to inspect: ")) - 1
            console.print(capture[seq])
            console.input("\nPress Enter to go back or Ctrl + C to quit...")

        except KeyboardInterrupt:
            console.print("\n[bold red]Closing...[/bold red]")
            break
        except Exception as e:
            console.print(f"[bold red]An error has occured: {type(e)}[/bold red]")

def main():
    interface = choose_interface()
    packet_filter = choose_filter()
    capture_packets(interface, packet_filter)
    show_packet_details()

main()
