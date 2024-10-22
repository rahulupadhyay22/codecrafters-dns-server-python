import socket
def main():
    print("Logs from your program will appear here!")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            rid = b"\x04\xd2"
            rflags = b"\x80\x00"
            qdcount = b"\x00\x01"
            header = rid + rflags + qdcount + (b"\x00" * 6)
            question = b"\x0ccodecrafters\x02io\x00\x00\x01\x00\x01"
            response = header + question
            
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break
        
if __name__ == "__main__":
    main()
