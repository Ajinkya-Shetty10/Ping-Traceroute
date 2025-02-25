import argparse
import socket
import struct
import time
import select
import sys

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_icmp_packet(id, seq, payload_size=56):
    header = struct.pack('!BBHHH', 8, 0, 0, id, seq)  # Type, Code, Checksum, ID, Sequence
    payload = b'a' * payload_size  # Payload
    chksum = checksum(header + payload)
    header = struct.pack('!BBHHH', 8, 0, chksum, id, seq)
    return header + payload

def ping(dest_addr, count, interval, timeout, packet_size):
    try:
        dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print(f"Could not resolve {dest_addr}")
        return

    print(f"PING {dest_addr} ({dest_ip}) {packet_size} bytes of data.")

    id = 12345  # Arbitrary ID
    seq = 0
    sent = 0
    received = 0

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
        s.settimeout(timeout)
        while True:
            if count and sent >= count:
                break

            packet = create_icmp_packet(id, seq, packet_size)
            s.sendto(packet, (dest_ip, 1))
            sent += 1
            start_time = time.time()

            ready = select.select([s], [], [], timeout)
            if ready[0]:
                try:
                    recv_packet, addr = s.recvfrom(1024)
                    received += 1
                    elapsed = (time.time() - start_time) * 1000
                    print(f"{len(recv_packet)} bytes from {addr[0]}: icmp_seq={seq} time={elapsed:.2f} ms")
                except socket.timeout:
                    print("Request timed out.")
            else:
                print("Request timed out.")

            seq += 1
            time.sleep(interval)

    print(f"\n--- {dest_addr} ping statistics ---")
    print(f"{sent} packets transmitted, {received} received, {((sent - received) / sent) * 100:.2f}% packet loss")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Custom Ping Implementation")
    parser.add_argument("-c", "--count", type=int, default=None, help="Number of packets to send")
    parser.add_argument("-i", "--interval", type=float, default=1, help="Interval between packets")
    parser.add_argument("-s", "--size", type=int, default=56, help="Packet size")
    parser.add_argument("-t", "--timeout", type=float, default=1, help="Timeout in seconds")
    parser.add_argument("destination", help="Destination IP or hostname")
    args = parser.parse_args()

    ping(args.destination, args.count, args.interval, args.timeout, args.size)