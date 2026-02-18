package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run portscanner.go <target> [start_port] [end_port]")
		fmt.Println("Example: go run portscanner.go 192.168.1.1")
		fmt.Println("Example: go run portscanner.go scanme.nmap.org 1 1000")
		os.Exit(1)
	}

	target := os.Args[1]
	startPort := 1
	endPort := 1024 

	if len(os.Args) >= 4 {
		startPort, _ = strconv.Atoi(os.Args[2])
		endPort, _ = strconv.Atoi(os.Args[3])
	}

	fmt.Printf("Port Scanner\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Target: %s\n", target)
	fmt.Printf("Scanning ports %d-%d\n", startPort, endPort)
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n")

	startTime := time.Now()

	
	openPorts := scanPorts(target, startPort, endPort)

	elapsed := time.Since(startTime)

	fmt.Printf("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("Scan completed in %s\n", elapsed)
	fmt.Printf("Found %d open ports\n", len(openPorts))
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

func scanPorts(target string, startPort, endPort int) []int {
	var openPorts []int
	var wg sync.WaitGroup
	var mu sync.Mutex

	maxWorkers := 100
	portChan := make(chan int, maxWorkers)

	// Start workers
	for range  maxWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				if scanPort(target, port) {
					mu.Lock()
					openPorts = append(openPorts, port)
					mu.Unlock()
					
					service := getServiceName(port)
					fmt.Printf("✓ Port %d is OPEN (%s)\n", port, service)
				}
			}
		}()
	}

	
	for port := startPort; port <= endPort; port++ {
		portChan <- port
	}
	close(portChan)

	wg.Wait()

	return openPorts
}

func scanPort(target string, port int) bool {
	address := fmt.Sprintf("%s:%d", target, port)
	
	conn, err := net.DialTimeout("tcp", address, 1*time.Second)
	if err != nil {
		return false // Port is closed or filtered
	}
	
	conn.Close()
	return true // Port is open
}

func getServiceName(port int) string {
	services := map[int]string{
		20:   "FTP-DATA",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
		8080: "HTTP-Proxy",
		8443: "HTTPS-Alt",
	}

	if service, exists := services[port]; exists {
		return service
	}
	return "Unknown"
}
