import socket
import base64
import struct
import os

MAGIC_SOF = b'---SOF---'
MAGIC_EOF = b'---EOF---'
HOST = 'localhost'
PORT = 1053
DIR_OUT ="..\\output\\"


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
    16 Bit: QDCOUNT - 0 question
    16 Bit: ANCOUNT - 1 answer
    16 Bit: NSCOUNT - 0 name server RR
    16 Bit: ARCOUNT - 0 additional records

    Returns:
        byterarray: randomized header
    """
    
    header = bytearray()

    id: bytes = get_id(bin_data)
    flags = b'\x01\x00'
    qdcount  = b'\x00\x00'
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

def gen_trailer() -> bytes:
    """add trailing bytes for dns packet:
    0x00 - terminate query
    0x0001 - QTYPE 'A': IPv4-Adress
    0x0001 - QCLASS 'IN': Intenet

    Returns:
        bytes: footer of dns packet
    """
    return bytes(b'\00\00\x01\x00\x01')
    



def get_id(bin_data:bytes) -> bytes:
    return int_to_bytes(bin_data[0],1)

def extract_data(data_stream:bytearray) -> bytearray:
    """remove length bytes from byte stream
     

    Args:
        data_stream (bytearray): received payload 

    Returns:
        bytearray: raw data 
    """
    payload = bytearray()
    # to_read: length of label
    to_read = data_stream[0]
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
    result:list[str] = []
    
    # current_len: length of chars to read
    current_len: int = bin_data[0]
    i = 0
    for byte in bin_data[1:]:
        if i < current_len:
            # print(byte)
            result.append(chr(byte))
            i += 1
        elif byte == 0:
            break
        else:
            result.append(".")
            current_len = byte
            i = 0

    return "".join(result)

if __name__=='__main__':


    data_array = bytearray()
    file_in = ""

    # create UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))

        # main loop
        while True:
            data, addr = sock.recvfrom(1024)

            # debug echo        
            #print("data received: %s" %data)
            # build answer
            sock.sendto(data, addr)

            # command received: start of file transfer
            if MAGIC_SOF in data:
                file_in = extract_strings(data[22:])
                print("Filetransfer requested.")
                print("Incoming file: %s" %(file_in))
    #            print("New incoming file: %s" %filename)    

            # command received: end of file transfer
            elif MAGIC_EOF in data:
                print("Filetransfer finished.")
                file_out = "recv_" + file_in
    #            print("File transfer finished. Creating new file: %s" %filename_out) 
                # stop server after file transfer
                break
            
            # no cammnd received: catch payload
            else:
                #print("data received: %s" %data)
                data = bytearray(data)
                # extract payload: remove header and trailer
                data_array += data[12:-5]

    
    file_out = DIR_OUT + file_out
    print("All data received. Writing data to file %s ..." %(file_out))
    payload: bytearray = extract_data(data_array)
    #print(payload)
    payload_decoded: bytes = base64.urlsafe_b64decode(payload)
    #print(payload_decoded)

    try:
        os.makedirs(DIR_OUT, exist_ok=True)
        with open(file_out, 'wb') as fobj:
            fobj.write(payload_decoded)
    except Exception as e:
        print("An error occured: %s" %(e))


