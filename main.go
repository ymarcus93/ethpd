// Command ethpd is an Ethereum UDP packet dissector for discovery protocol v4.
//
// Pass a pcap file to the command and it will print to stdout the decoded packets.
// For larger pcap files, pipe out to a text file.
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/ethereum/go-ethereum/rlp"
)

var (
	pcapFile = os.Args[1]
	handle   *pcap.Handle
	err      error
)

// Packet sizes
const (
	macSize  = 256 / 8           // 32
	sigSize  = 520 / 8           // 65 (512-bit signature + 1 byte more for recovery id)
	headSize = macSize + sigSize // space of packet frame data
)

// Packet types
const (
	pingPacket = iota + 1 // zero is 'reserved'
	pongPacket
	findnodePacket
	neighborsPacket
)

// Packet data structures
type (
	ping struct {
		Version    uint
		From, To   rpcEndpoint
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// pong is the reply to ping.
	pong struct {
		// This field should mirror the UDP envelope address
		// of the ping packet, which provides a way to discover the
		// the external address (after NAT).
		To rpcEndpoint

		ReplyTok   []byte // This contains the hash of the ping packet.
		Expiration uint64 // Absolute timestamp at which the packet becomes invalid.
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// findnode is a query for nodes close to the given target.
	findnode struct {
		Target     NodeID // doesn't need to be an actual public key
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}

	// reply to findnode
	neighbors struct {
		Nodes      []rpcNode
		Expiration uint64
		// Ignore additional fields (for forward compatibility).
		Rest []rlp.RawValue `rlp:"tail"`
	}
)

type (
	rpcNode struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
		ID  NodeID
	}

	rpcEndpoint struct {
		IP  net.IP // len 4 for IPv4 or 16 for IPv6
		UDP uint16 // for discovery protocol
		TCP uint16 // for RLPx protocol
	}
)

// NodeID is a unique identifier for each node.
// The node identifier is a marshaled elliptic curve public key.
// 512 bits.
type NodeID [64]byte

// String() returns NodeID as a long hexadecimal number.
func (n NodeID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// recoverNodeID computes the public key used to sign the
// given hash from the signature.
func recoverNodeID(hash, sig []byte) (id NodeID, err error) {
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	if err != nil {
		return id, err
	}
	if len(pubkey)-1 != len(id) {
		return id, fmt.Errorf("recovered pubkey has %d bits, want %d bits", len(pubkey)*8, (len(id)+1)*8)
	}
	for i := range id {
		id[i] = pubkey[i+1]
	}
	return id, nil
}

// decode takes the payload and decodes it into one of the
// ethereum packet data structures.
//
// Returns unknown type error, if data cannot be decoded
func decode(buf []byte) (hash []byte, p interface{}, id NodeID, err error) {
	if len(buf) < headSize+1 {
		return hash, p, id, errors.New("packet too small")
	}
	hash, sig, sigdata := buf[:macSize], buf[macSize:headSize], buf[headSize:]
	shouldhash := crypto.Keccak256(buf[macSize:])
	if !bytes.Equal(hash, shouldhash) {
		return hash, p, id, errors.New("bad hash")
	}
	fromID, err := recoverNodeID(crypto.Keccak256(buf[headSize:]), sig)
	if err != nil {
		return hash, p, id, err
	}
	switch ptype := sigdata[0]; ptype {
	case pingPacket:
		p = new(ping)
	case pongPacket:
		p = new(pong)
	case findnodePacket:
		p = new(findnode)
	case neighborsPacket:
		p = new(neighbors)
	default:
		return hash, p, id, fmt.Errorf("unknown type: %d", ptype)
	}
	s := rlp.NewStream(bytes.NewReader(sigdata[1:]), 0)
	err = s.Decode(p)
	return hash, p, fromID, err
}

// printPacket will print the decoded packet to the
// standard output.
func printPacket(packet gopacket.Packet, index int) {
	fmt.Println("----------------------------------------")

	// Get packet information
	ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	lengthPacket := packet.Metadata().Length
	payload := packet.Layers()[3].LayerContents()

	// Print initial info
	fmt.Println("Timestamp:", packet.Metadata().Timestamp.Format("01/02/2006 3:04:05.000000PM"))
	fmt.Println("Packet #:", index)
	fmt.Println("Source:", ip.SrcIP)
	fmt.Println("Destination:", ip.DstIP)
	fmt.Println("Packet length:", lengthPacket)

	// Decode payload
	hash, decodedPayload, fromID, err := decode(payload)
	if err != nil {
		fmt.Println("ERROR: ", err)
	} else { // Print payload data
		var packetType string
		switch ptype := reflect.TypeOf(decodedPayload).String(); ptype { // Set packetType to correct value
		case "*main.ping":
			packetType = "Ping"
		case "*main.pong":
			packetType = "Pong"
		case "*main.findnode":
			packetType = "FindNode"
		case "*main.neighbors":
			packetType = "Neighbors"
		default:
			packetType = "Unknown"
		}
		fmt.Println("Packet type:", packetType)
		fmt.Println("Packet signed by:", fromID)
		fmt.Println("Hash of packet:", hex.EncodeToString(hash))

		// Print certain items of the decoded packets (depends on type)
		if packetType == "Neighbors" {
			nodesData := reflect.ValueOf(decodedPayload).Elem().FieldByName("Nodes")
			fmt.Printf("Nodes: (%v)\n", nodesData.Len())
			for i := 0; i < nodesData.Len(); i++ {
				ipString := nodesData.Index(i).FieldByName("IP").Addr().Interface()
				nodeUDP := nodesData.Index(i).FieldByName("UDP")
				nodeTCP := nodesData.Index(i).FieldByName("TCP")
				nodeID := nodesData.Index(i).FieldByName("ID").Interface()
				fmt.Println(ipString, "- UDP:", nodeUDP, "- TCP:", nodeTCP, "- ID:", nodeID)
				if i != nodesData.Len()-1 {
					fmt.Println()
				}
			}
			fmt.Println()
			exp := time.Unix(int64(reflect.ValueOf(decodedPayload).Elem().FieldByName("Expiration").Uint()), 0)
			fmt.Println("Expiration:", exp)
		}

		if packetType == "FindNode" {
			fmt.Println("Target:", reflect.ValueOf(decodedPayload).Elem().FieldByName("Target").Interface())
			exp := time.Unix(int64(reflect.ValueOf(decodedPayload).Elem().FieldByName("Expiration").Uint()), 0)
			fmt.Println("Expiration:", exp)
		}

		if packetType == "Pong" {
			pongData := reflect.ValueOf(decodedPayload).Elem().FieldByName("To")
			ipString := pongData.FieldByName("IP").Addr().Interface()
			udpPort := pongData.FieldByName("UDP")
			tcpPort := pongData.FieldByName("TCP")
			fmt.Println("Pong to IP:", ipString, "UDP:", udpPort, "TCP:", tcpPort)
			replyK := hex.EncodeToString(reflect.ValueOf(decodedPayload).Elem().FieldByName("ReplyTok").Bytes())
			fmt.Println("ReplyToK:", replyK)
			exp := time.Unix(int64(reflect.ValueOf(decodedPayload).Elem().FieldByName("Expiration").Uint()), 0)
			fmt.Println("Expiration:", exp)
		}

		if packetType == "Ping" {
			pingDataTo := reflect.ValueOf(decodedPayload).Elem().FieldByName("To")
			ipStringTo := pingDataTo.FieldByName("IP").Addr().Interface()
			udpPortTo := pingDataTo.FieldByName("UDP")
			tcpPortTo := pingDataTo.FieldByName("TCP")
			fmt.Println("Ping to IP:", ipStringTo, "UDP:", udpPortTo, "TCP:", tcpPortTo)

			pingDataFrom := reflect.ValueOf(decodedPayload).Elem().FieldByName("From")
			ipStringFrom := pingDataFrom.FieldByName("IP").Addr().Interface()
			udpPortFrom := pingDataFrom.FieldByName("UDP")
			tcpPortFrom := pingDataFrom.FieldByName("TCP")
			fmt.Println("Ping from IP:", ipStringFrom, "UDP:", udpPortFrom, "TCP:", tcpPortFrom)

			exp := time.Unix(int64(reflect.ValueOf(decodedPayload).Elem().FieldByName("Expiration").Uint()), 0)
			fmt.Println("Expiration:", exp)

			fmt.Println("Version:", reflect.ValueOf(decodedPayload).Elem().FieldByName("Version"))
		}
	} // End print payload data
}

func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	fmt.Printf("Time: %s", elapsed)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ethpd <pcapFile>")
	}
	defer timeTrack(time.Now())
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	defer handle.Close() // Close file stream after main() finishes

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	decodedPackets := 0
	for packet := range packetSource.Packets() {
		i++
		checkUDP := packet.Layer(layers.LayerTypeUDP)
		if checkUDP != nil { // eth Packet
			printPacket(packet, i)
			decodedPackets++
		}
	}
	fmt.Println("----------------------------------------")
	fmt.Println("# of packets:", i)
	fmt.Println("# of decoded packets:", decodedPackets)
}
