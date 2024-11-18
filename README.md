# dnstunnel

## Disclaimer

This tool is for educational purposes only. Use this tool only at your own systems and consider all local laws and regulations.

## Goal

dnstunnel implements a data tunnel via DNS over UDP. 

## Versions

V0.1 first working product:
  - supports all filetypes
  - send content of the file via valid dns packages from source to target
  - packages are echo'ed to check the correct transmission
  - packeges will be resent if the echo was different from the sent package
