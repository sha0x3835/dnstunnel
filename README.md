# dnstunnel

## Disclaimer

This tool is for educational purposes only. Use this tool only at your own systems and consider all local laws and regulations.

## Goal

dnstunnel implements a data tunnel via DNS over UDP. 

## Needed modifications

- server.py:
  - change output directory: DIR_OUT
  - change host: HOST
  - change port: PORT
- client.py
  - change server host: S_HOST
  - change server port: S_PORT


## Versions

V0.1 first working product:
  - supports all filetypes
  - send content of the file via valid dns packages from source to target
  - packages are echo'd

V0.2 improved functionality:
  - server respond to query with valid DNS packet
  - SHA-256 hash validation of echo'd packets
  - waiting for response to ensure correct order

V0.3 Bug fix:
  - response id is now updated and is taken from query


## Requirements

`python3`

# Usage

1. copy `server.py` to prefered location where the file shall be transfered to
2. copy `client.py` to prefered location
3. modify `server.py`: Variable `HOST` to the host address of the server machine
4. modify `server.py`: Variable `DIR_OUT` to the directory, the transfered file shall be written
5. modify `client.py`: Variable `S_HOST` to the host address of the server machine
6. run `python server.py`
7. run `python client.py <file>` where `<file>` specified the path to the file which shall be transfered

