'''
DNS Header: https://www.rfc-editor.org/rfc/rfc1035
                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

'''
import socket
import random
import struct
import base64
import sys
import re

S_HOST = 'localhost'
S_PORT = 1053

MAX_INT_BYTE = 65535
LEN_MAX_CHUNK = 62
MAGIC_SOF = b'---SOF---'
MAGIC_EOF = b'---EOF---'


def int_to_bytes(value: int, number:int) -> bytes:
    """converts integer to bytes

    Args:
        value (int): integer to convert

    Returns:
        bytes: byte representation of integer
    """
    
    # >: Big endian
    # I: unsigned int (2 Bytes size)
    # H: unsigned short (2 Bytes size)
    # c: char (1 Bytes size)
    if number == 1:
        return struct.pack('>B', value)
    if number == 2:
        return struct.pack('>H', value)
    
    return struct.pack('>I', value)





def gen_header() -> bytearray:
    """generate header for dns packet:
    16 Bit: random query id
    16 Bit: flags - standard query
    16 Bit: QDCOUNT - 1 question
    16 Bit: ANCOUNT - 0 answer
    16 Bit: NSCOUNT - 0 name server RR
    16 Bit: ARCOUNT - 0 additional records

    Returns:
        byterarray: randomized header
    """
    
    header = bytearray()

    id: bytes = int_to_bytes(random.randint(1, MAX_INT_BYTE), 2)
    flags = b'\x01\x00'
    qdcount  = b'\x00\x01'
    ancount  = b'\x00\x00'
    nscount  = b'\x00\x00'
    arcount  = b'\x00\x00'

    header += id
    header += flags
    header += qdcount
    header += ancount
    header += nscount
    header += arcount
    return header

def gen_trailer() -> bytes:
    """add trailing bytes for dns packet:
    0x00 - terminate query
    0x0001 - QTYPE 'A': IPv4-Adress
    0x0001 - QCLASS 'IN': Intenet

    Returns:
        bytes: footer of dns packet
    """
    return bytes(b'\00\00\x01\x00\x01')
    

def gen_bytes_dns_query_from_filename(name:str) -> bytearray:
    """generate bytes from filename in DNS query format: 
    1Byte: length of query
    encoded string

    Args:
        name (str): specified filename

    Returns:
        bytearray: dns query ready bytes
    """
    parts = name.strip("\n").split('.')
    data = bytearray()
    for part in parts:
        data += int_to_bytes(len(part),1)
        data += part.encode('ascii')
    
    return data

def gen_magic_data(magic:bytes, filename:str) -> bytearray:
    """generate magic string in DNS query format

    Args:
        magic (bytes): magic string which is processed on server side to perform actions, 
        defined globally
        

    Returns:
        bytearray: dns query ready bytes
    """
    data = bytearray()
    data += int_to_bytes(len(magic),1)
    data += magic
    data += gen_bytes_dns_query_from_filename(filename)
    return data


def build_dns_packet(data:bytearray) -> bytearray:
    """build dns query from provided data:
    1. header
    2. query data
    3. trailer

    Args:
        data (bytearray): data to send in correct format:
        - max length = 255 Byte
        - for each chunk: leading size

    Returns:
        bytearray: well formed query
    """
    dns_payload = bytearray()
    dns_payload += gen_header()
    dns_payload += data
    dns_payload += gen_trailer()    
    return dns_payload

def gen_data_chunks(bin_data:bytes) -> list[bytearray]:
    """divide data into chunks with len <= 63 each

    Args:
        bin_data (bytes): data divide

    Returns:
        list[bytearray]: list of chunks
    """
    result:list[bytearray] = []

    curr_bytes = bytearray()
    i_bytes = 0
    for byte in bin_data:
        i_bytes += 1
        
        curr_bytes.append(byte)
        
        # maximum length reached
        if i_bytes == LEN_MAX_CHUNK:
            curr_bytes = bytearray(int_to_bytes(i_bytes, 1)) + curr_bytes
            result.append(curr_bytes)
            curr_bytes = bytearray()
            i_bytes = 0
        
    # process rest of data
    curr_bytes = bytearray(int_to_bytes(i_bytes, 1)) + curr_bytes
    result.append(curr_bytes)

    return result

def build_chunk_packets(chunks:list[bytearray]) -> list[bytearray]:
    """join maximum four chunks in packets

    Args:
        chunks (list[bytearray]): list of chunks

    Returns:
        list[bytearray]: list of chunk packets
    """
    result:list[bytearray] = []
    
    packet = bytearray()
    for i, chunk in enumerate(chunks, start=1):
        packet += chunk
        if i % 4 == 0:
            result.append(packet)
            packet = bytearray()
    
    result.append(packet)
    return result


if __name__ == '__main__':
    
    try:
        file_in: str = sys.argv[1]
    except:
        print("ERROR: no input file given.")
        print("Usage: dnstunnel <file>")
        sys.exit()
    
    input_data = bytearray()

    try:
        
        with open(file_in, 'rb') as fobj:    
            input_data +=  fobj.read()
    
    except IOError:
        print("File %s does not exist or you don't have access rights" %(file_in))
        sys.exit()
    except:
        print("An unknown Error occured")
        sys.exit()

    file_in_name = re.split(r'[/\\]+', file_in)[-1]
    file_in_name = file_in_name.replace(" ", "_")
    
    # encode data with base64url
    data_encoded: bytes = base64.urlsafe_b64encode(input_data)

    # list of chunks (<=63 Byte each)
    chunk_list: list[bytearray] = gen_data_chunks(data_encoded)

    # create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((S_HOST, S_PORT))
            sock.settimeout(5)
        except socket.error as exc:
            print("Caught exception socket.error : %s" %(exc))

        print("Start to send %s to %s:%i" %(file_in_name, S_HOST, S_PORT))
        start_msg: bytearray = gen_magic_data(MAGIC_SOF, file_in_name)
        payload: bytearray = build_dns_packet(start_msg) 
        
        # send SOF command to server
        sock.send(payload)
        
        packets: list[bytearray] = build_chunk_packets(chunk_list)
        
        print("%i packets to send." %(len(packets)))
        
        for i, packet in enumerate(packets, start=1):
            payload = build_dns_packet(packet)
            
            # print("Send packet %i" %(i) )
            
            # send data    
            sock.send(payload)
        
        # sock.send(message)
        # response, addr = sock.recvfrom(1024)
        # print(response)

        
        print("File transfer finished.")
        end_msg = gen_magic_data(MAGIC_EOF, file_in_name)
        payload = build_dns_packet(end_msg) 
        
        # send EOF command to server
        sock.send(payload)
        
    print("NORMAL TERMINATION")
        
        
