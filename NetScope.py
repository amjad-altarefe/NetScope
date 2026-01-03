import pyshark
import json
from rich.table import Table
from rich.console import Console

console = Console()

INTERFACE = r"\Device\NPF_{enter your interface}"
OUTPUT_FILE = "captured_packets.json"


def choose_filter():
    print("Choose capture filter:")
    print("1 - TCP")
    print("2 - UDP")
    print("3 - ICMP")
    print("4 - All packets")

    choice = input("Enter choice: ").strip()

    if choice == "1":
        return "tcp"
    elif choice == "2":
        return "udp"
    elif choice == "3":
        return "icmp"
    else:
        return None   # all packets


def capture_packets(packet_filter):
    packets_list = []

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        display_filter=packet_filter
    )

    seq = 1
    table = Table(title="Live Packet Capture (updating...)")
    table.add_column("SEQ#", style="bold cyan")
    table.add_column("Source IP", style="green")
    table.add_column("Source Port", style="yellow")
    table.add_column("Source MAC", style="magenta")
    table.add_column("Destination IP", style="green")
    table.add_column("Destination Port", style="yellow")
    table.add_column("Destination MAC", style="magenta")
    table.add_column("Protocol", style="red")

    try:
        for pkt in capture.sniff_continuously(packet_count=50):
            try:
                src_ip = pkt.ip.src if hasattr(pkt, "ip") else "N/A"
                dst_ip = pkt.ip.dst if hasattr(pkt, "ip") else "N/A"

                src_mac = pkt.eth.src if hasattr(pkt, "eth") else "N/A"
                dst_mac = pkt.eth.dst if hasattr(pkt, "eth") else "N/A"

                protocol = pkt.highest_layer

                src_port = "N/A"
                dst_port = "N/A"

                if protocol == "TCP":
                    src_port = pkt.tcp.srcport
                    dst_port = pkt.tcp.dstport
                elif protocol == "UDP":
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

                # Update the screen with the schedule
                console.clear()
                console.print(table)

                packets_list.append({
                    "seq": seq,
                    "source_ip": src_ip,
                    "source_port": src_port,
                    "source_mac": src_mac,
                    "destination_ip": dst_ip,
                    "destination_port": dst_port,
                    "destination_mac": dst_mac,
                    "protocol": protocol
                })

                seq += 1

            except Exception:
                continue

    except KeyboardInterrupt:
        console.print("[bold red]Capture stopped by user[/bold red]")

    finally:
        capture.close()
    
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            json.dump(packets_list, f, indent=4)

        console.print(f"\n[bold green]Packets saved to {OUTPUT_FILE}[/bold green]")


def show_packet_details():
    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
        packets = json.load(f)

    while True:
        try:
            seq_num = int(input("\nEnter packet sequence number (0 to exit): "))

            if seq_num == 0:
                console.print("[bold green]Exiting packet lookup.[/bold green]")
                break

            found = False
            for pkt in packets:
                if pkt["seq"] == seq_num:
                    table = Table(title=f"Packet Details - SEQ {seq_num}", show_lines=True)
                    table.add_column("Field", style="cyan", no_wrap=True)
                    table.add_column("Value", style="magenta")
                    for key, value in pkt.items():
                        table.add_row(key, str(value))
                    console.print(table)
                    found = True
                    break

            if not found:
                console.print(f"[bold red]Packet with SEQ {seq_num} not found.[/bold red]")

        except ValueError:
            console.print("[bold yellow]Please enter a valid number.[/bold yellow]")



def main():
    packet_filter = choose_filter()
    capture_packets(packet_filter)
    show_packet_details()


if __name__ == "__main__":
    main()
