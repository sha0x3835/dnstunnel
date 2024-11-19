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
import hashlib
import time

S_HOST: str = 'localhost'
S_PORT: int = 53

MAX_INT_BYTE: int = 65535
LEN_MAX_CHUNK: int = 62
TIMEOUT: int = 5
MAGIC_SOF: bytes = b'---SOF---'
MAGIC_EOF: bytes = b'---EOF---'


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
    
    header:bytearray = bytearray()

    id: bytes = int_to_bytes(value=random.randint(1, MAX_INT_BYTE), number=2)
    flags: bytes = b'\x01\x00'
    qdcount: bytes  = b'\x00\x01'
    ancount: bytes  = b'\x00\x00'
    nscount: bytes  = b'\x00\x00'
    arcount: bytes  = b'\x00\x00'

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
    0x001c - QTYPE 'AAAA': IPv6-Adress
    0x0001 - QCLASS 'IN': Intenet

    Returns:
        bytes: footer of dns packet
    """
    return bytes(b'\00\00\x1c\x00\x01')
    

def gen_bytes_dns_query_from_filename(name:str) -> bytearray:
    """generate bytes from filename in DNS query format: 
    1Byte: length of query
    encoded string

    Args:
        name (str): specified filename

    Returns:
        bytearray: dns query ready bytes
    """
    parts: list[str] = name.strip("\n").split('.')
    
    data = bytearray()
    
    for part in parts:
        data += int_to_bytes(value=len(part),number=1)
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
    data: bytearray = bytearray()
    
    data += int_to_bytes(len(magic),1)
    data += magic
    data += gen_bytes_dns_query_from_filename(filename)
    
    return data


def build_query_packet(data:bytearray) -> bytearray:
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
    dns_payload: bytearray = bytearray()
    
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
    curr_bytes: bytearray = bytearray()
    
    i_bytes: int = 0
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
    packet: bytearray = bytearray()
    
    for i, chunk in enumerate(chunks, start=1):
        packet += chunk
        if i % 4 == 0:
            result.append(packet)
            packet = bytearray()
    
    result.append(packet)
    
    return result

def response_is_valid(data_sent:bytearray, data_recv:bytes, counter:int) -> bool:
    """checks the integrity of received packet
    
    - extract received payload (ignore DNS header, query trailer and answer) 
        - ignore 12 Byte Header
        - ignore 32 Byte trailer : 16 Byte address, 2 Byte length, 4 Byte TTL, 2 Byte class, 2 Byte type, 2 byte name, 5 Byte query trailer
    - read received hash value: answer section of DNS response (16 Byte)
    - read packet number: from TTL in DNS response (before answer data and length of data)

    Used hash algorithm: SHA-256
    Only compare first 16 Byte 

    Robust checking against bit flips: server received correct data if
      case 1: server side calculated hash of received payload == hash of sent payload
      or
      case 2: echo'd  payload == sent payload

    Args:
        data_sent (bytearray): _description_
        data_recv (bytes): _description_
        counter (int): _description_

    Returns:
        bool: True: if
                received hash value == hash value of sent packet 
                or 
                hash of received data == hash of sent data
              
              False: otherwise
    """
    
    # hash of sent payload (ignore header and trailer)
    hash_sent: bytes = hashlib.sha256(data_sent[12:-5]).digest()
    # hash of received payload (ignore header, query trailer and answer)
    hash_data_recv: bytes = hashlib.sha256(data_recv[12:-33]).digest()
    # received hash value: last 16 Byte
    hash_recv: bytes = data_recv[-16:]
    # received TTL value
    counter_recv: bytes = data_recv[-22:-18]
    
    # counter = 4 Byte value
    counter = counter % pow(2,32)
    
    if counter != int.from_bytes(bytes=counter_recv, byteorder='big'):
        
        print("Warning: processed packet %i didn't match with received packet %i" 
              %(counter, int.from_bytes(counter_recv, byteorder='big'))
              )
    
    if (hash_sent[:16] == hash_recv) or (hash_sent == hash_data_recv):
        print("Packet %i: i.O." %(counter))
        return True
    
    print("WARNING: Hash value of packet %i didn't match" %(counter))
    return False

def wait_for_response() -> None:
    time_start: float = time.time()
    
    while(True):
        if (time_start + TIMEOUT < time.time()):
            print("WARNING: Timeout at packet %i" %(counter))
            break
        
        response: bytes = sock.recv(1024)
        
        if not response_is_valid(data_sent=payload, data_recv=response, counter=counter):
            print("Warning: at packet %i a failure occured!" %(counter))
        
        break
    

if __name__ == '__main__':
    
    try:
        file_in: str = sys.argv[1]
    except:
        print("ERROR: no input file given.")
        print("Usage: dnstunnel <file>")
        sys.exit()
    
    input_data = bytearray()

    try:
        
        with open(file=file_in, mode='rb') as fobj:    
            input_data +=  fobj.read()
    
    except IOError:
        print("File %s does not exist or you don't have access rights" %(file_in))
        sys.exit()
    except:
        print("An unknown Error occured")
        sys.exit()

    file_in_name = re.split(pattern=r'[/\\]+', string=file_in)[-1]
    file_in_name = file_in_name.replace(" ", "_")
    
    # encode data with base64url
    data_encoded: bytes = base64.urlsafe_b64encode(input_data)

    # list of chunks (<=63 Byte each)
    chunk_list: list[bytearray] = gen_data_chunks(data_encoded)

    counter: int = 0
    # create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect((S_HOST, S_PORT))
            sock.settimeout(TIMEOUT)
            
        except socket.error as exc:
            print("Caught exception socket.error : %s" %(exc))

        print("Start to send %s to %s:%i" %(file_in_name, S_HOST, S_PORT))
        start_msg: bytearray = gen_magic_data(MAGIC_SOF, file_in_name)
        payload: bytearray = build_query_packet(start_msg) 
        
        # send SOF command to server
        sock.send(payload)

        # check response        
        wait_for_response()
        # while(True):
            # if (time_start + TIMEOUT < time.time()):
            #     print("WARNING: Timeout at packet %i" %(counter))
            #     break

            # response: bytes = sock.recv(1024)
            # if not response_is_valid(data_sent=payload, data_recv=response, counter=counter):
            #     print("Warning: at packet %i a failure occured!" %(counter))
            # break
        
        counter += 1
        
        
        
        packets: list[bytearray] = build_chunk_packets(chunk_list)
        
        print("%i packets to send." %(len(packets)))
        
        for i, packet in enumerate(packets, start=1):
            payload = build_query_packet(packet)
            
            # print("Send packet %i" %(i) )
            
            # send data    
            sock.send(payload)

            # check response        
            wait_for_response()                
            
            counter += 1
        
        print("File transfer finished.")
        end_msg = gen_magic_data(MAGIC_EOF, file_in_name)
        payload = build_query_packet(end_msg) 
        
        # send EOF command to server
        sock.send(payload)
        counter += 1
        

        
    print("NORMAL TERMINATION")
        
        
