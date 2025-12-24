package main

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// Config holds MikroTik connection settings
type Config struct {
	Host        string
	Port        string
	Username    string
	Password    string
	AddressList string
	Timeout     string
	UseTLS      bool
}

// RouterOSClient represents a connection to MikroTik RouterOS
type RouterOSClient struct {
	conn   net.Conn
	reader io.Reader
	writer io.Writer
}

// Word represents a RouterOS API word/sentence component
type Word struct {
	Data string
}

func main() {
	// Setup logging to syslog/file for OSSEC integration
	logFile, err := os.OpenFile("/var/ossec/logs/active-responses.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.SetOutput(os.Stderr)
	} else {
		defer logFile.Close()
		log.SetOutput(logFile)
	}

	// Parse configuration from environment or config file
	config := Config{
		Host:        getEnvOrDefault("MIKROTIK_HOST", "192.168.88.1"),
		Port:        getEnvOrDefault("MIKROTIK_PORT", "8728"),
		Username:    getEnvOrDefault("MIKROTIK_USER", "admin"),
		Password:    getEnvOrDefault("MIKROTIK_PASS", ""),
		AddressList: getEnvOrDefault("MIKROTIK_LIST", "ossec_blocked"),
		Timeout:     getEnvOrDefault("MIKROTIK_TIMEOUT", "24h"),
		UseTLS:      getEnvOrDefault("MIKROTIK_TLS", "false") == "true",
	}

	// OSSEC passes: action, user, source IP, alert ID, rule ID, agent, etc.
	if len(os.Args) < 4 {
		log.Printf("Usage: %s <action> <user> <source_ip> [alert_id] [rule_id]\n", os.Args[0])
		os.Exit(1)
	}

	action := os.Args[1]
	srcIP := os.Args[3]

	// Validate IP address
	if net.ParseIP(srcIP) == nil {
		log.Printf("Invalid IP address: %s\n", srcIP)
		os.Exit(1)
	}

	log.Printf("OSSEC Active Response - Action: %s, IP: %s\n", action, srcIP)

	// Connect to MikroTik
	client, err := NewRouterOSClient(config)
	if err != nil {
		log.Printf("Failed to connect to MikroTik: %v\n", err)
		os.Exit(1)
	}
	defer client.Close()

	// Authenticate
	if err := client.Login(config.Username, config.Password); err != nil {
		log.Printf("Failed to authenticate: %v\n", err)
		os.Exit(1)
	}

	// Execute action
	switch action {
	case "add":
		if err := client.AddToAddressList(srcIP, config.AddressList, config.Timeout); err != nil {
			log.Printf("Failed to add IP to address list: %v\n", err)
			os.Exit(1)
		}
		log.Printf("Successfully added %s to address list '%s'\n", srcIP, config.AddressList)

	case "delete":
		if err := client.RemoveFromAddressList(srcIP, config.AddressList); err != nil {
			log.Printf("Failed to remove IP from address list: %v\n", err)
			os.Exit(1)
		}
		log.Printf("Successfully removed %s from address list '%s'\n", srcIP, config.AddressList)

	default:
		log.Printf("Unknown action: %s\n", action)
		os.Exit(1)
	}
}

// NewRouterOSClient creates a new RouterOS API client
func NewRouterOSClient(config Config) (*RouterOSClient, error) {
	address := net.JoinHostPort(config.Host, config.Port)
	var conn net.Conn
	var err error

	if config.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,
		}
		conn, err = tls.Dial("tcp", address, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", address, 10*time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}

	return &RouterOSClient{
		conn:   conn,
		reader: conn,
		writer: conn,
	}, nil
}

// Close closes the connection
func (c *RouterOSClient) Close() error {
	return c.conn.Close()
}

// Login authenticates with RouterOS
func (c *RouterOSClient) Login(username, password string) error {
	// Send login command
	if err := c.sendSentence([]string{"/login", "=name=" + username, "=password=" + password}); err != nil {
		return err
	}

	// Read response
	reply, err := c.readSentence()
	if err != nil {
		return err
	}

	// Check for !done (success) or !trap (error)
	if len(reply) > 0 && reply[0] == "!done" {
		return nil
	}

	// Try MD5 challenge-response auth (older RouterOS versions)
	if len(reply) > 0 && strings.HasPrefix(reply[0], "!done") {
		for _, word := range reply {
			if strings.HasPrefix(word, "=ret=") {
				challenge := strings.TrimPrefix(word, "=ret=")
				response := c.encodePassword(password, challenge)

				if err := c.sendSentence([]string{"/login", "=name=" + username, "=response=" + response}); err != nil {
					return err
				}

				reply, err := c.readSentence()
				if err != nil {
					return err
				}

				if len(reply) > 0 && reply[0] == "!done" {
					return nil
				}
			}
		}
	}

	return fmt.Errorf("login failed: %v", reply)
}

// AddToAddressList adds an IP to a MikroTik address list
func (c *RouterOSClient) AddToAddressList(ip, listName, timeout string) error {
	// Check if IP already exists in the list
	exists, err := c.checkIPInList(ip, listName)
	if err != nil {
		return err
	}

	if exists {
		log.Printf("IP %s already in list %s\n", ip, listName)
		return nil
	}

	// Add IP to address list
	command := []string{
		"/ip/firewall/address-list/add",
		"=list=" + listName,
		"=address=" + ip,
		"=comment=OSSEC Block: " + time.Now().Format(time.RFC3339),
	}

	if timeout != "" && timeout != "0" {
		command = append(command, "=timeout="+timeout)
	}

	if err := c.sendSentence(command); err != nil {
		return err
	}

	reply, err := c.readSentence()
	if err != nil {
		return err
	}

	if len(reply) > 0 && strings.HasPrefix(reply[0], "!trap") {
		return fmt.Errorf("error adding to address list: %v", reply)
	}

	return nil
}

// RemoveFromAddressList removes an IP from a MikroTik address list
func (c *RouterOSClient) RemoveFromAddressList(ip, listName string) error {
	// Find the entry ID
	if err := c.sendSentence([]string{
		"/ip/firewall/address-list/print",
		"?list=" + listName,
		"?address=" + ip,
	}); err != nil {
		return err
	}

	var entryID string
	for {
		reply, err := c.readSentence()
		if err != nil {
			return err
		}

		if len(reply) == 0 {
			continue
		}

		if reply[0] == "!done" {
			break
		}

		if strings.HasPrefix(reply[0], "!re") {
			for _, word := range reply {
				if strings.HasPrefix(word, "=.id=") {
					entryID = strings.TrimPrefix(word, "=.id=")
					break
				}
			}
		}
	}

	if entryID == "" {
		return fmt.Errorf("IP %s not found in list %s", ip, listName)
	}

	// Remove the entry
	if err := c.sendSentence([]string{
		"/ip/firewall/address-list/remove",
		"=.id=" + entryID,
	}); err != nil {
		return err
	}

	reply, err := c.readSentence()
	if err != nil {
		return err
	}

	if len(reply) > 0 && strings.HasPrefix(reply[0], "!trap") {
		return fmt.Errorf("error removing from address list: %v", reply)
	}

	return nil
}

// checkIPInList checks if an IP exists in an address list
func (c *RouterOSClient) checkIPInList(ip, listName string) (bool, error) {
	if err := c.sendSentence([]string{
		"/ip/firewall/address-list/print",
		"?list=" + listName,
		"?address=" + ip,
		"=count-only=",
	}); err != nil {
		return false, err
	}

	for {
		reply, err := c.readSentence()
		if err != nil {
			return false, err
		}

		if len(reply) == 0 {
			continue
		}

		if reply[0] == "!done" {
			return false, nil
		}

		if strings.HasPrefix(reply[0], "!re") {
			return true, nil
		}
	}
}

// sendSentence sends a sentence (command) to RouterOS
func (c *RouterOSClient) sendSentence(words []string) error {
	for _, word := range words {
		if err := c.sendWord(word); err != nil {
			return err
		}
	}
	// Send empty word to mark end of sentence
	return c.sendWord("")
}

// sendWord sends a single word
func (c *RouterOSClient) sendWord(word string) error {
	length := len(word)

	// Encode length
	var lengthBytes []byte
	if length < 0x80 {
		lengthBytes = []byte{byte(length)}
	} else if length < 0x4000 {
		lengthBytes = []byte{byte(length>>8) | 0x80, byte(length)}
	} else if length < 0x200000 {
		lengthBytes = []byte{byte(length>>16) | 0xC0, byte(length >> 8), byte(length)}
	} else if length < 0x10000000 {
		lengthBytes = []byte{byte(length>>24) | 0xE0, byte(length >> 16), byte(length >> 8), byte(length)}
	} else {
		lengthBytes = []byte{0xF0, byte(length >> 24), byte(length >> 16), byte(length >> 8), byte(length)}
	}

	if _, err := c.writer.Write(lengthBytes); err != nil {
		return err
	}

	if length > 0 {
		if _, err := c.writer.Write([]byte(word)); err != nil {
			return err
		}
	}

	return nil
}

// readSentence reads a sentence (response) from RouterOS
func (c *RouterOSClient) readSentence() ([]string, error) {
	var sentence []string

	for {
		word, err := c.readWord()
		if err != nil {
			return nil, err
		}

		if word == "" {
			break
		}

		sentence = append(sentence, word)
	}

	return sentence, nil
}

// readWord reads a single word
func (c *RouterOSClient) readWord() (string, error) {
	lengthBuf := make([]byte, 1)
	if _, err := io.ReadFull(c.reader, lengthBuf); err != nil {
		return "", err
	}

	length := int(lengthBuf[0])
	bytesToRead := 0

	if length&0x80 == 0 {
		bytesToRead = length
	} else if length&0xC0 == 0x80 {
		lengthBuf2 := make([]byte, 1)
		if _, err := io.ReadFull(c.reader, lengthBuf2); err != nil {
			return "", err
		}
		bytesToRead = ((length & ^0x80) << 8) + int(lengthBuf2[0])
	} else if length&0xE0 == 0xC0 {
		lengthBuf2 := make([]byte, 2)
		if _, err := io.ReadFull(c.reader, lengthBuf2); err != nil {
			return "", err
		}
		bytesToRead = ((length & ^0xC0) << 16) + (int(lengthBuf2[0]) << 8) + int(lengthBuf2[1])
	} else if length&0xF0 == 0xE0 {
		lengthBuf2 := make([]byte, 3)
		if _, err := io.ReadFull(c.reader, lengthBuf2); err != nil {
			return "", err
		}
		bytesToRead = ((length & ^0xE0) << 24) + (int(lengthBuf2[0]) << 16) + (int(lengthBuf2[1]) << 8) + int(lengthBuf2[2])
	} else if length == 0xF0 {
		lengthBuf2 := make([]byte, 4)
		if _, err := io.ReadFull(c.reader, lengthBuf2); err != nil {
			return "", err
		}
		bytesToRead = (int(lengthBuf2[0]) << 24) + (int(lengthBuf2[1]) << 16) + (int(lengthBuf2[2]) << 8) + int(lengthBuf2[3])
	}

	if bytesToRead == 0 {
		return "", nil
	}

	wordBuf := make([]byte, bytesToRead)
	if _, err := io.ReadFull(c.reader, wordBuf); err != nil {
		return "", err
	}

	return string(wordBuf), nil
}

// encodePassword creates MD5 challenge-response for authentication
func (c *RouterOSClient) encodePassword(password, challenge string) string {
	h := md5.New()
	h.Write([]byte{0})
	h.Write([]byte(password))

	challengeBytes, _ := hex.DecodeString(challenge)
	h.Write(challengeBytes)

	return "00" + hex.EncodeToString(h.Sum(nil))
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
