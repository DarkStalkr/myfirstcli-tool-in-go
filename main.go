package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

// DNSHeader represents the header section of a DNS message
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSQuestion represents a question in the DNS message
type DNSQuestion struct {
	Name  []byte
	Type  uint16
	Class uint16
}

// DNSAnswer represents an answer record in the DNS response
type DNSAnswer struct {
	Name     []byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

func readUserInput(prompt string) string {
	// Create a new scanner to read from standard input
	scanner := bufio.NewScanner(os.Stdin)

	// Print the prompt
	fmt.Print(prompt)

	// Read the input
	scanner.Scan()

	// Return the input, trimming any whitespace
	return strings.TrimSpace(scanner.Text())
}

func encodeDomainName(domain string) []byte {
	var encoded []byte
	parts := strings.Split(domain, ".")

	for _, part := range parts {
		encoded = append(encoded, byte(len(part)))
		encoded = append(encoded, []byte(part)...)
	}

	encoded = append(encoded, 0) // Add terminating zero
	return encoded
}

func buildQuery(domain string, queryType uint16) []byte {
	header := DNSHeader{
		ID:      uint16(os.Getpid()),
		Flags:   0x0100,
		QDCount: 1,
		ANCount: 0,
		NSCount: 0,
		ARCount: 0,
	}

	question := DNSQuestion{
		Name:  encodeDomainName(domain),
		Type:  queryType,
		Class: 1,
	}

	query := make([]byte, 0, 512)

	// Append header
	query = append(query, byte(header.ID>>8), byte(header.ID))
	query = append(query, byte(header.Flags>>8), byte(header.Flags))
	query = append(query, byte(header.QDCount>>8), byte(header.QDCount))
	query = append(query, byte(header.ANCount>>8), byte(header.ANCount))
	query = append(query, byte(header.NSCount>>8), byte(header.NSCount))
	query = append(query, byte(header.ARCount>>8), byte(header.ARCount))

	// Append question
	query = append(query, question.Name...)
	query = append(query, byte(question.Type>>8), byte(question.Type))
	query = append(query, byte(question.Class>>8), byte(question.Class))

	return query
}

// parseHeader decodes the DNS header from the response
func parseHeader(response []byte) DNSHeader {
	return DNSHeader{
		ID:      uint16(response[0])<<8 | uint16(response[1]),
		Flags:   uint16(response[2])<<8 | uint16(response[3]),
		QDCount: uint16(response[4])<<8 | uint16(response[5]),
		ANCount: uint16(response[6])<<8 | uint16(response[7]),
		NSCount: uint16(response[8])<<8 | uint16(response[9]),
		ARCount: uint16(response[10])<<8 | uint16(response[11]),
	}
}

// skipQuestion skips over the question section in the response
func skipQuestion(response []byte, offset int) int {
	// Skip domain name
	for offset < len(response) {
		length := int(response[offset])
		if length == 0 {
			offset++
			break
		}
		if length&0xC0 == 0xC0 {
			offset += 2
			break
		}
		offset += length + 1
	}
	// Skip type and class
	return offset + 4
}

// parseAnswer decodes an IP address from a DNS answer section
func parseAnswer(response []byte, offset int) (string, int) {
	// Skip name field (using message compression)
	if response[offset]&0xC0 == 0xC0 {
		offset += 2
	} else {
		for offset < len(response) {
			length := int(response[offset])
			if length == 0 {
				offset++
				break
			}
			offset += length + 1
		}
	}

	// Skip type, class, and TTL
	offset += 8

	// Get record data length
	rdLength := int(uint16(response[offset])<<8 | uint16(response[offset+1]))
	offset += 2

	// For A records (IPv4), create IP address string
	if rdLength == 4 {
		ip := net.IPv4(
			response[offset],
			response[offset+1],
			response[offset+2],
			response[offset+3],
		)
		return ip.String(), offset + rdLength
	}

	return "", offset + rdLength
}

func main() {
	for {
		// Prompt user for domain name
		domain := readUserInput("Enter domain name (or 'exit' to quit): ")

		// Check if user wants to exit
		if strings.ToLower(domain) == "exit" {
			fmt.Println("Goodbye!")
			break
		}

		// Validate input
		if domain == "" {
			fmt.Println("Domain name cannot be empty. Please try again.")
			continue
		}

		// Build and send query
		query := buildQuery(domain, 1) // Type 1 for A records

		conn, err := net.Dial("udp", "8.8.8.8:53")
		if err != nil {
			fmt.Printf("Failed to connect: %v\n", err)
			continue
		}

		_, err = conn.Write(query)
		if err != nil {
			fmt.Printf("Failed to send query: %v\n", err)
			conn.Close()
			continue
		}

		// Receive response
		response := make([]byte, 512)
		n, err := conn.Read(response)
		conn.Close()

		if err != nil {
			fmt.Printf("Failed to receive response: %v\n", err)
			continue
		}

		// Parse response
		header := parseHeader(response[:n])
		offset := 12 // Skip header

		// Skip question section
		offset = skipQuestion(response[:n], offset)

		// Parse answers
		fmt.Printf("\nIP Addresses for %s:\n", domain)
		for i := 0; i < int(header.ANCount); i++ {
			if ip, newOffset := parseAnswer(response[:n], offset); ip != "" {
				fmt.Printf("- %s\n", ip)
				offset = newOffset
			}
		}
		fmt.Println()
	}
}
