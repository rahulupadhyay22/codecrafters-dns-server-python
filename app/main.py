import socket
import struct
def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            # Unpack the DNS query header
            id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
                "!HHHHHH", buf[:12]
            )
            
            # Add the question section
            name = b"\x0ccodecrafters\x02io\x00"
            qtype = struct.pack("!H", 1)
            qclass = struct.pack("!H", 1)
            question = name + qtype + qclass

            # Create a DNS response
            response = struct.pack(
                "!6H", id, (flags & 0x0100) | 0x8000, qdcount, 1, nscount, arcount
            )
            response += question
            response += name
            response += struct.pack("!2H", 1, 0x0001)  # TYPE and CLASS
            response += struct.pack("!I", 60)  # TTL
            response += struct.pack("!H", 4)  # RDLENGTH
            response += socket.inet_aton("8.8.8.8")  # RDATA
            
            
            # Send the DNS response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
        
        
if __name__ == "__main__":
    main()

