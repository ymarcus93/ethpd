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

## Version 4 Packet Structure
[See RLPx protocol page for more information](https://github.com/ethereum/devp2p/blob/master/rlpx.md)

* All packets are signed with **ECDSA-secp256k1** keys (represents a node's ID)
	- For authenticity
	- _Signature:_ sign(privkey, sha3(packet-type || packet-data))
		- 65-byte compact ECDSA signature containing the recovery id as the last element.
		- See the [code](https://github.com/ethereum/go-ethereum/blob/master/crypto/secp256k1/secp256.go#L68) for more information on how NodeID is recovered from the signature.
* All packets are prepended with SHA3-256 hash of the underlying data of the packet
	- For integrity
	- _Hash:_ sha3(signature || packet-type || packet-data)
	- 32 bytes
* _Packet Type:_ Single byte < 2**7 // valid values are [1,4]

<u>Full UDP Packet Payload:</u> hash || signature || packet-type || packet-data

### Packet Data ###
[RLPx](https://github.com/ethereum/devp2p/blob/master/rlpx.md#node-discovery) encoded list. Packet properties are serialized in the order in which they're defined.

#### _Ping_ ####
* Version
* From, To (IP, UDP, TCP)
* Expiration

#### _Pong_ ####
* To (IP, UDP, TCP)
* ReplyTok
* Expiration

#### _Findnode_ ####
* Target
* Expiration

#### _Neighbors_ ####
* Nodes:
	- IP
	- UDP
	- TCP
	- ID
* Expiration