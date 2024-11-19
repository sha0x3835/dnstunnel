import socket
import base64
import struct
import os
import hashlib

MAGIC_SOF: bytes = b'---SOF---'
MAGIC_EOF: bytes = b'---EOF---'
HOST: str = 'localhost'
PORT: int = 53
DIR_OUT: str ="..\\output\\"


def int_to_bytes(value: int, number:int) -> bytes:
    """converts integer to bytes

    Args:
        value (int): value to convert
        number (int): number of bytes to generate

    Returns:
        bytes: byte representation of integer with given length
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

def gen_header(bin_data:bytes) -> bytearray:
    """generate header for dns packet:
    16 Bit: random query id
    16 Bit: flags - standard query
    16 Bit: QDCOUNT - 1 question
    16 Bit: ANCOUNT - 1 answer
    16 Bit: NSCOUNT - 0 name server RR
    16 Bit: ARCOUNT - 0 additional records

    Returns:
        byterarray: randomized header
    """
    
    header = bytearray()

    id: bytes = bin_data[0:2]
    flags = b'\x81\x80'
    qdcount  = b'\x00\x01'
    ancount  = b'\x00\x01'
    nscount  = b'\x00\x00'
    arcount  = b'\x00\x00'

    header += id
    header += flags
    header += qdcount
    header += ancount
    header += nscount
    header += arcount
    return header

def extract_data(data_stream:bytearray) -> bytearray:
    """remove length bytes from byte stream
     

    Args:
        data_stream (bytearray): received payload 

    Returns:
        bytearray: raw data 
    """
    payload = bytearray()
    
    # to_read: length of label
    to_read: int = data_stream[0]
    for byte in data_stream[1:]:
        if to_read == 0:
            to_read = int(byte)
            continue
        payload.append(byte)
        to_read -= 1

    return payload

def extract_strings(bin_data:bytes) -> str:
    """extract command info:
    - filename

    Args:
        bin_data (bytes): received payload

    Returns:
        str: filename
    """
    result: list[str] = []
    
    # current_len: length of chars to read
    current_len: int = bin_data[0]
    i = 0
    for byte in bin_data[1:]:
        if i < current_len:
            result.append(chr(byte))
            i += 1
        elif byte == 0:
            break
        else:
            result.append(".")
            current_len = byte
            i = 0

    return "".join(result)


def gen_answer(hash_value:bytes, msg_counter:int) -> bytearray:
    """build answer fields
        
        name: identifier for answer name section, 0x0c: Offset 12 Byte from start of query section -> skip header
        resp_type: 'AAAA'
        resp_class: IN
        ttl: ttl used for received packet number: value is mod(2^32) to ensure 4Byte length
        data_length: 128 Bit = 16 Byte (only use first 16 Byte)

    Args:
        hash_value (bytes): 128 Bit hashvalue 
        msg_counter (int): 32 bit integer

    Returns:
        bytearray: _description_
    """

    response = bytearray()
    # 0xc0: identifier for answer name section, 0x0c: Offset 12 Byte from start of query section -> skip header
    name: bytes = bytes(b'\xc0\x0c')
    # AAAA
    resp_type: bytes = bytes(b'\x00\x1c') 
    # IN
    resp_class: bytes = bytes(b'\x00\x01')
    # ttl used for received packet number
    ttl: bytes = int_to_bytes(msg_counter%pow(2,32), 4 )
    # 128 Bit = 16 Byte
    data_length: bytes = bytes(b'\x00\x10')
    # hashvalue bytes
    
    
    address: bytes = hash_value[:16]
    
    response += name
    response += resp_type
    response += resp_class
    response += ttl
    response += data_length
    response += address
    
    return response
    
def build_response_packet(header:bytes, query:bytes, answer:bytearray) -> bytearray:
    response: bytearray = bytearray()
    
    response += header
    response += query
    response += answer
    
    return response
    
    
    
if __name__=='__main__':
    """server implementation of dnstunnel

    """


    data_array: bytearray = bytearray()
    file_in: str = ""

    # create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))

        # main loop
        counter: int = 0
        response_header: bytearray = bytearray()

        while True:
            data, addr = sock.recvfrom(1024)
            if not counter:
                response_header += gen_header(data)

            # command received: start of file transfer
            if MAGIC_SOF in data:
                file_in: str = extract_strings(data[22:])
                
                print("Filetransfer requested from %s:%i" %(addr[0], addr[1]))
                print("Incoming file: %s" %(file_in))

            # command received: end of file transfer
            elif MAGIC_EOF in data:
                print("Filetransfer finished.")
                
                file_out = "recv_" + file_in

                # stop server after file transfer
                break
            
            # no cammnd received: catch payload
            else:
                # extract payload: remove header and trailer
                data_array += bytearray(data[12:-5])

            # compute sha256-hash (128bit) from payload
            data_hash: bytes = hashlib.sha256(data[12:-5]).digest()[:16] 
            
            # response = data + hash
            response: bytearray = build_response_packet(header=response_header, query=data[12:], answer=gen_answer(data_hash, counter))
            
            sock.sendto(response, addr)
            counter += 1
            

    
    file_out: str = DIR_OUT + file_out

    print("All data received. Writing data to file %s ..." %(file_out))

    payload: bytearray = extract_data(data_array)
    payload_decoded: bytes = base64.urlsafe_b64decode(payload)

    try:
        os.makedirs(DIR_OUT, exist_ok=True)
        
        with open(file=file_out, mode='wb') as fobj:
            fobj.write(payload_decoded)
            
    except Exception as e:
        print("An error occured: %s" %(e))


