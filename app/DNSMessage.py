import struct
import socket as socket
from itertools import chain
from typing import List, NamedTuple, Tuple

class DNSMessage(NamedTuple):
    header: 'DNSHeader'
    questions: List['DNSQuestion']
    answers: List['DNSResourceRecord']

    @staticmethod
    def pack_name(name: str) -> bytes:
        packed = b''
        for label in name.split('.'):
            length = len(label)
            packed += struct.pack(f'B{length}s', length, label.encode())
        return packed + b'\x00'
    
    @staticmethod
    def unpack_name(buf: bytes, offset=0) -> Tuple[str, int]:
        labels = []
        while buf[offset]:
            if buf[offset] >> 6 == 0b11:
                pointer = struct.unpack("!H", buf[offset: offset+2])[0]
                pointer_offset = (pointer & 0x3FFF) - 12
                labels.append( DNSMessage.unpack_name(buf, pointer_offset)[0] )
                offset += 1; break
            else:
                length = buf[offset]
                labels.append( buf[offset+1: offset+length+1].decode() )
                offset += length + 1
        return '.'.join(labels), offset + 1
   
    @staticmethod
    def unpack(buf: bytes):
        header = DNSHeader.unpack(buf[:12])
        questions, offset = DNSQuestion.unpack(buf[12:], header.qdcount)
        answers = DNSResourceRecord.unpack(buf, offset)
        return DNSMessage(header, questions, answers)

    def forward(self, resolver: str) -> 'DNSMessage':
        return DNSMessage(
            self.header.respond(),
            self.questions,
            list(chain.from_iterable(
                q.forward(resolver, self.header) for q in self.questions
            ))
        )

    def pack(self) -> bytes:
        return (
            self.header.pack() 
          + b''.join(q.pack() for q in self.questions)
          + b''.join(rr.pack() for rr in self.answers)
        )
    
    def respond(self) -> 'DNSMessage':
        return DNSMessage(
            self.header.respond(),
            self.questions,
            [q.respond() for q in self.questions],
        )

class DNSHeader(NamedTuple):
    id: int; qr: int; opcode: int; aa: int; tc: int; rd: int; ra: int; z: int; rcode: int
    qdcount: int; ancount: int; nscount: int; arcount: int

    @staticmethod
    def unpack(buf: bytes) -> 'DNSHeader':
        id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", buf[:12])
        return DNSHeader(
            id,
            flags >> 15 & 1,
            flags >> 11 & 0b1111,
            flags >> 10 & 1,
            flags >> 9 & 1,
            flags >> 8 & 1,
            flags >> 7 & 1,
            flags >> 4 & 0b111,
            flags & 0b1111,
            qdcount, ancount, nscount, arcount
        )

    def pack(self) -> bytes:
        flags = (
            (self.qr     << 15)
          | (self.opcode << 11)
          | (self.aa     << 10)
          | (self.tc     <<  9)
          | (self.rd     <<  8)
          | (self.ra     <<  7)
          | (self.z      <<  4)
          |  self.rcode
        )
        return struct.pack('!HHHHHH', self.id, flags, self.qdcount, self.ancount, self.nscount, self.arcount)
    
    def respond(self) -> 'DNSHeader':
        rcode = self.opcode and 4
        return DNSHeader(
            self.id, 1, self.opcode, 0, 0, self.rd, 0, 0, rcode, self.qdcount, self.qdcount, 0, 0
        )

class DNSQuestion(NamedTuple):
    name: str
    type: int
    cls: int

    @staticmethod
    def unpack(buf: bytes, qdcount: int) -> Tuple[List['DNSQuestion'], int]:
        questions, offset = [], 0
        for _ in range(qdcount):
            name, offset = DNSMessage.unpack_name(buf, offset)
            type, cls = struct.unpack("!HH", buf[offset: offset+4])
            questions.append( DNSQuestion(name, type, cls) )
            offset += 4
        return questions, offset + 12
    
    def forward(self, resolver: str, header: 'DNSHeader') -> List['DNSResourceRecord']:
        single = DNSMessage(header._replace(qdcount=1), [self], [])
        tup = tuple(resolver.split(':'))
        address = tup[0], int(tup[1])

        print(f'📤 Calling resolver at {address}:')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as resolver_socket:
            resolver_socket.sendto(single.pack(), address)
            result = DNSMessage.unpack(resolver_socket.recv(512))
            print('⭐️', result.questions, '\n')
            return result.answers

    def pack(self) -> bytes:
        return (
            DNSMessage.pack_name(self.name)
          + struct.pack('!HH', self.type, self.cls)
        )

    def respond(self) -> 'DNSResourceRecord':
        return DNSResourceRecord(
            self.name, 1, 1, 60, 4, struct.pack("!BBBB", 8, 8, 8, 8)
        )

class DNSResourceRecord(NamedTuple):
    name: str
    type: int
    cls: int
    ttl: int
    rdlength: int
    rdata: bytes

    @staticmethod
    def unpack(buf: bytes, offset: int) -> List['DNSResourceRecord']:
        if len(buf[offset:]) < 14: return []
        name, offset = DNSMessage.unpack_name(buf, offset)
        return [ DNSResourceRecord(name, *struct.unpack(f'!HHIH4s', buf[offset:])) ]

    def pack(self) -> bytes:
        return (
            DNSMessage.pack_name(self.name)
          + struct.pack(f'!HHIH{len(self.rdata)}s', self.type, self.cls, self.ttl, self.rdlength, self.rdata)
        ) 