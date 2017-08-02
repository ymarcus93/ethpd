# ethpd
Ethereum UDP packet dissector for discovery protocol v4.

`ethpd` decodes a pcap file of captured Ethereum packets into a readable format.
The decoded packets will be printed to the standard output. Pipe the output to a text file for larger pcap files.

## Usage
`ethpd [pcapFile]` -- Prints to standard output

`ethpd [pcapFile] > file.txt` -- Prints to text file `file.txt`

## Install

With a [correctly configured](https://golang.org/doc/code.html#GOPATH) Go installation:

```
go get -u github.com/ymarcus93/ethpd
```

Alternatively, download the provided binary in the Releases tab.