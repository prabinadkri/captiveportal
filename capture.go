package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os/exec"
    "time"
    "io"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (
    device          = "enp0s3" // Change to your network interface
    snapshotLen     = int32(1600)
    promiscuous     = false
    timeout         = 30 * time.Second
    handle          *pcap.Handle
    activeSessions  = make(map[string]bool) // Track logged-in devices by IP
    internalNetwork = "10.0.2.0/24"     // Change this to match your network
    internalIPNet   *net.IPNet
    serverIP        net.IP
    captivePortalIP = "10.0.2.4"        // Change to your captive portal server IP
    captivePortalPort = "8080"          // Change to your captive portal port
)
type Resource struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

func init() {
    // Parse the internal network range
    _, ipNet, err := net.ParseCIDR(internalNetwork)
    if err != nil {
        log.Fatal("Invalid internal network range:", err)
    }
    internalIPNet = ipNet
}

func getServerIP(device string) (net.IP, error) {
    iface, err := net.InterfaceByName(device)
    if err != nil {
        return nil, err
    }

    addrs, err := iface.Addrs()
    if err != nil {
        return nil, err
    }

    for _, addr := range addrs {
        ipNet, ok := addr.(*net.IPNet)
        if ok && !ipNet.IP.IsLoopback() {
            if ipNet.IP.To4() != nil {
                return ipNet.IP, nil
            }
        }
    }

    return nil, fmt.Errorf("no IPv4 address found for interface %s", device)
}

func main() {
    // Get the server's IP address
    var err error
    serverIP, err = getServerIP(device)
    if err != nil {
        log.Fatal("Failed to get server IP:", err)
    }
    log.Println("Server IP:", serverIP)

    // Open the network device for packet capture
    handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    // Start a goroutine to periodically fetch active sessions and restricted resources
    go fetchActiveSessions()

    
    err = handle.SetBPFFilter("tcp")
    if err != nil {
        log.Fatal(err)
    }

    // Initialize iptables by flushing existing rules and setting up initial chains
    initializeIptables()

    // Start processing packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        processPacket(packet)
    }
}

// initializeIptables sets up the initial iptables configuration
func initializeIptables() {
    // Flush existing rules
    exec.Command("iptables", "-F").Run()
    exec.Command("iptables", "-t", "nat", "-F").Run()
    
    // Set default policies
    exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
    exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
    exec.Command("iptables", "-P", "OUTPUT", "ACCEPT").Run()
    
    log.Println("Initialized iptables rules")
}

// fetchActiveSessions periodically fetches active sessions and restricted resources
func fetchActiveSessions() {
    for {
        // Fetch all restricted resources for active sessions
        resp, err := http.Get("http://localhost:8080/api/allRestrictedResources")
        if err != nil {
            log.Println("Error fetching all restricted resources:", err)
            time.Sleep(5 * time.Second)
            continue
        }
        defer resp.Body.Close()

        // Read the response body
        body, err := io.ReadAll(resp.Body)
        if err != nil {
            log.Println("Error reading response body:", err)
            time.Sleep(5 * time.Second)
            continue
        }

        
        log.Println("Response:", string(body))

        // Decode the JSON response
        var allRestrictedResources map[string][]Resource
        if err := json.Unmarshal(body, &allRestrictedResources); err != nil {
            log.Println("Error decoding all restricted resources:", err)
            time.Sleep(5 * time.Second)
            continue
        }

        // Update iptables rules based on active sessions and restricted resources
        for clientIP, resources := range allRestrictedResources {
            // Allow Internet access for authenticated clients
            if err := allowInternetAccess(clientIP); err != nil {
                log.Println("Error allowing internet access:", err)
            }

            
            var restrictedResourceIPs []string
            for _, resource := range resources {
                restrictedResourceIPs = append(restrictedResourceIPs, resource.IPAddress)
            }

            // Add restricted resource rules for the client
            if err := blockRestrictedResources(clientIP, restrictedResourceIPs); err != nil {
                log.Println("Error blocking restricted resources:", err)
            }
        }

        time.Sleep(5 * time.Second)
    }
}

// processPacket processes each captured packet
func processPacket(packet gopacket.Packet) {
    // Get the IP layer
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer == nil {
        return
    }
    ip, _ := ipLayer.(*layers.IPv4)

    // Skip packets from the server itself
    if ip.SrcIP.Equal(serverIP) {
        return
    }

    // Check if the source IP is internal
    if isInternalIP(ip.SrcIP) {
        clientIP := ip.SrcIP.String()

        // Check if the client is authenticated
        if !activeSessions[clientIP] {
            // Block Internet access for unauthenticated clients
            if err := blockInternetAccess(clientIP); err != nil {
                log.Println("Error blocking internet access:", err)
            }
        } else {
            // Allow Internet access for authenticated clients
            if err := allowInternetAccess(clientIP); err != nil {
                log.Println("Error allowing internet access:", err)
            }
        }
    }
}

// isInternalIP checks if an IP address belongs to the internal network
func isInternalIP(ip net.IP) bool {
    return internalIPNet.Contains(ip)
}

// blockInternetAccess blocks all internet access for a client except captive portal access
func blockInternetAccess(clientIP string) error {
    // Check if the drop rule already exists
    exists, err := dropRuleExists(clientIP)
    if err != nil {
        return err
    }
    
    if !exists {
        // 1. Add redirection rules for HTTP and HTTPS to captive portal
        // HTTP redirection
        cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-j", "DNAT", 
                           "--to-destination", captivePortalIP+":"+captivePortalPort)
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // HTTPS redirection
        cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-j", "DNAT", 
                          "--to-destination", captivePortalIP+":"+captivePortalPort)
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // 2. Allow DNS queries (port 53) for domain resolution
        cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }
        
        cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // 3. Allow DHCP (for IP renewal)
        cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // 4. Allow access to captive portal
        cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-d", captivePortalIP, "--dport", "8080","-j", "ACCEPT")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        
        // 5. Drop all other forwarded traffic
        cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-j", "DROP")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        log.Printf("Blocked internet access for client: %s\n", clientIP)
    }
    
    return nil
}

// allowInternetAccess removes internet access restrictions for a client
func allowInternetAccess(clientIP string) error {
    // 1. Remove HTTP redirection
    cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-j", "DNAT", 
                       "--to-destination", captivePortalIP+":"+captivePortalPort)
    cmd.Run() // Ignore errors as the rule might not exist

    // 2. Remove HTTPS redirection
    cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-j", "DNAT", 
                      "--to-destination", captivePortalIP+":"+captivePortalPort)
    cmd.Run() // Ignore errors as the rule might not exist

    // 3. Remove DNS rules
    cmd = exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
    cmd.Run() // Ignore errors as the rule might not exist
    
    cmd = exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-p", "tcp", "--dport", "53", "-j", "ACCEPT")
    cmd.Run() // Ignore errors as the rule might not exist

  
    cmd = exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT")
    cmd.Run() // Ignore errors as the rule might not exist

   
    cmd = exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-d", captivePortalIP, "-j", "ACCEPT")
    cmd.Run() // Ignore errors as the rule might not exist

    // 6. Remove drop rule
    cmd = exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-j", "DROP")
    cmd.Run() // Ignore errors as the rule might not exist

    log.Printf("Allowed internet access for client: %s\n", clientIP)
    return nil
}

// blockRestrictedResources blocks access to specific resources for a client
func blockRestrictedResources(clientIP string, restrictedResources []string) error {
	// Step 1: Remove all existing rules for the client IP
	

	// Step 2: Block access to restricted resources
	for _, resource := range restrictedResources {
        
		cmd := exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-d", resource, "-j", "DROP")
		log.Println("Executing:", cmd.String())
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to block resource %s for client %s: %v", resource, clientIP, err)
		}
	}

	// Step 3: Allow access to all other resources
	allResources, err := getAllResources()
	if err != nil {
		return fmt.Errorf("failed to fetch all resources: %v", err)
	}

	for _, resource := range allResources {
		// Skip if the resource is in the restricted list
		if contains(restrictedResources, resource) {
			continue
		}

		// Remove any existing DROP rule for this resource (if it exists)
		cmd := exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-d", resource, "-j", "DROP")
		log.Println("Executing:", cmd.String())
		cmd.Run() // Ignore errors, as the rule might not exist

		// Allow access to this resource
		cmd = exec.Command("iptables", "-A", "FORWARD", "-s", clientIP, "-d", resource, "-j", "ACCEPT")
		log.Println("Executing:", cmd.String())
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to allow access to resource %s for client %s: %v", resource, clientIP, err)
		}
	}

	log.Printf("Updated restricted resources for client: %s\n", clientIP)
	return nil
}
// contains checks if a string exists in a slice of strings
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
func getAllResources() ([]string, error) {
	// Make a GET request to the /api/allResources endpoint
	resp, err := http.Get("http://localhost:8080/api/allResources")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resources: %v", err)
	}
	defer resp.Body.Close()

	// Decode the response into a slice of Resource structs
	var resources []Resource
	if err := json.NewDecoder(resp.Body).Decode(&resources); err != nil {
		return nil, fmt.Errorf("failed to decode resources: %v", err)
	}

	// Extract the IP addresses from the resources
	var ipAddresses []string
	for _, resource := range resources {
		ipAddresses = append(ipAddresses, resource.IPAddress)
	}

	return ipAddresses, nil
}
// unblockRestrictedResources removes restricted resource blocks for a client
func unblockRestrictedResources(clientIP string, resources []string) error {
    for _, resource := range resources {
        
        cmd := exec.Command("iptables", "-D", "FORWARD", "-s", clientIP, "-d", resource, "-j", "DROP")
        cmd.Run() // Ignore errors as the rule might not exist
    }
    return nil
}

// Helper functions to check if rules exist
func dropRuleExists(clientIP string) (bool, error) {
    cmd := exec.Command("iptables", "-C", "FORWARD", "-s", clientIP, "-j", "DROP")
    if err := cmd.Run(); err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            // Exit code 1 means the rule does not exist
            if exitError.ExitCode() == 1 {
                return false, nil
            }
        }
        return false, err
    }
    return true, nil
}

func restrictedRuleExists(clientIP string, resource string) (bool, error) {
    cmd := exec.Command("iptables", "-C", "FORWARD", "-s", clientIP, "-d", resource, "-j", "DROP")
    if err := cmd.Run(); err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            // Exit code 1 means the rule does not exist
            if exitError.ExitCode() == 1 {
                return false, nil
            }
        }
        return false, err
    }
    return true, nil
}