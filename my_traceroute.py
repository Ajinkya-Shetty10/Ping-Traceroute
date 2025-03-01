import argparse
import socket
import struct
import time
import select

def traceroute(dest_addr, max_hops, numeric, nqueries, summary):
    """Perform traceroute to a destination address using UDP packets.

    :param str dest_addr: Destination hostname or IP address
    :param int max_hops: Maximum number of hops to trace
    :param bool numeric: If True, show numeric IP addresses only
    :param int nqueries: Number of probe packets per TTL
    :param bool summary: If True, print summary of unanswered probes
    :return: None (Prints traceroute results to console)
    :rtype: None
    """
    try:
        dest_ip = socket.gethostbyname(dest_addr)
    except socket.gaierror:
        print(f"Could not resolve {dest_addr}")
        return

    print(f"traceroute to {dest_addr} ({dest_ip}), {max_hops} hops max")

    port = 33434  # Default port for traceroute
    ttl = 1

    while ttl <= max_hops:
        print(f"{ttl:2d}", end=" ")
        for _ in range(nqueries):
            # Create a raw socket
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

            # Send a UDP packet
            s.sendto(b'', (dest_ip, port))

            start_time = time.time()
            ready = select.select([s], [], [], 1)
            if ready[0]:
                try:
                    recv_packet, addr = s.recvfrom(1024)
                    elapsed = (time.time() - start_time) * 1000
                    if numeric:
                        print(f"{addr[0]} {elapsed:.2f} ms", end=" ")
                    else:
                        try:
                            hostname = socket.gethostbyaddr(addr[0])[0]
                            print(f"{hostname} ({addr[0]}) {elapsed:.2f} ms", end=" ")
                        except socket.herror:
                            print(f"{addr[0]} {elapsed:.2f} ms", end=" ")
                except socket.timeout:
                    print("*", end=" ")
            else:
                print("*", end=" ")
            s.close()
        print()
        ttl += 1

if __name__ == "__main__":
    """Command-line interface for the traceroute utility."""
    parser = argparse.ArgumentParser(description="Custom Traceroute Implementation")
    parser.add_argument("-n", action="store_true", help="Print numeric addresses")
    parser.add_argument("-q", "--nqueries", type=int, default=3, help="Number of probes per TTL")
    parser.add_argument("-S", action="store_true", help="Print summary of unanswered probes")
    parser.add_argument("destination", help="Destination IP or hostname")
    args = parser.parse_args()

    traceroute(args.destination, 30, args.n, args.nqueries, args.S)