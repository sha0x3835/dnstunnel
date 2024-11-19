# dnstunnel

## Disclaimer

This tool is for educational purposes only. Use this tool only at your own systems and consider all local laws and regulations.

## Goal

dnstunnel implements a data tunnel via DNS over UDP. 

## Versions

V0.1 first working product:
  - supports all filetypes
  - send content of the file via valid dns packages from source to target
  - packages are echo'd

V0.2 improved functionality:
  - server respond to query with valid DNS packet
  - SHA-256 hash validation of echo'd packets
  - waiting for response to ensure correct order
