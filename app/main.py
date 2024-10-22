import socket
from argparse import ArgumentParser
from app.DNSMessage import DNSMessage

def main(port=2053):
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(('127.0.0.1', port))
    print(f"✌️  Listening on port {port}.")

    parser = ArgumentParser()
    parser.add_argument('--resolver', type=str)
    args = parser.parse_args()

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            query = DNSMessage.unpack(buf)
            print(f'📥 Received a query from {source}:')
            print('⭐️', query.header)
            print('⭐️', query.questions)
            print()

            response = (
                query.forward(args.resolver) 
                if args.resolver else 
                query.respond()
            )
            print(f'📤 Sending a reponse to {source}:')
            print('⭐️', response.header)
            print('⭐️', response.questions)
            print('⭐️', response.answers)
            print('\n')
            udp_socket.sendto(response.pack(), source)
            
        except Exception as e:
            print(f'Error receiving data: {e}')
            break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('👋 Shutting down.')