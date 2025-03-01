package main

import (
    "encoding/json"
    "fmt"
    "log"
    "net"
    "net/http"
    "os/exec"
    "time"

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
)

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

    // Set a BPF filter to capture only HTTP traffic (port 80)
    err = handle.SetBPFFilter("tcp and port 80")
    if err != nil {
        log.Fatal(err)
    }

    // Start processing packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        processPacket(packet)
    }
}

// fetchActiveSessions periodically fetches active sessions and restricted resources
func fetchActiveSessions() {
    for {
        // Fetch active sessions
        resp, err := http.Get("http://localhost:8080/api/activeSessions")
        if err != nil {
            log.Println("Error fetching active sessions:", err)
            time.Sleep(5 * time.Second)
            continue
        }
        defer resp.Body.Close()

        var sessions map[string]bool
        if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
            log.Println("Error decoding active sessions:", err)
            time.Sleep(5 * time.Second)
            continue
        }

        // Update iptables rules based on active sessions
        for clientIP, isActive := range sessions {
            if isActive {
                // Remove redirect rules for authenticated clients
                if err := removeRedirectRule(clientIP); err != nil {
                    log.Println("Error removing redirect rules:", err)
                }

                // Fetch restricted resources for the client
                resp, err := http.Get("http://localhost:8080/api/check")
                if err != nil {
                    log.Println("Error fetching restricted resources:", err)
                    continue
                }
                defer resp.Body.Close()

                var data map[string]interface{}
                if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
                    log.Println("Error decoding restricted resources:", err)
                    continue
                }

                // Extract restricted resources from the response
                resources := data["resources"].([]interface{})
                var restrictedResources []string
                for _, resource := range resources {
                    resourceMap := resource.(map[string]interface{})
                    restrictedResources = append(restrictedResources, resourceMap["ip_address"].(string))
                }

                // Remove restricted resource rules for the client
                if err := removeRestrictedResourceRules(clientIP, restrictedResources); err != nil {
                    log.Println("Error removing restricted resource rules:", err)
                }
            } else {
                // Add redirect rules for unauthenticated clients
                if err := addRedirectRule(clientIP); err != nil {
                    log.Println("Error adding redirect rules:", err)
                }

                // Fetch restricted resources for the client
                resp, err := http.Get("http://localhost:8080/api/check")
                if err != nil {
                    log.Println("Error fetching restricted resources:", err)
                    continue
                }
                defer resp.Body.Close()

                var data map[string]interface{}
                if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
                    log.Println("Error decoding restricted resources:", err)
                    continue
                }

                // Extract restricted resources from the response
                resources := data["resources"].([]interface{})
                var restrictedResources []string
                for _, resource := range resources {
                    resourceMap := resource.(map[string]interface{})
                    restrictedResources = append(restrictedResources, resourceMap["ip_address"].(string))
                }

                // Add restricted resource rules for the client
                if err := addRestrictedResourceRules(clientIP, restrictedResources); err != nil {
                    log.Println("Error adding restricted resource rules:", err)
                }
            }
        }

        activeSessions = sessions
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
            // Add redirect rules for unauthenticated clients
            if err := addRedirectRule(clientIP); err != nil {
                log.Println("Error adding redirect rules:", err)
            }
        } else {
            // Remove redirect rules for authenticated clients
            if err := removeRedirectRule(clientIP); err != nil {
                log.Println("Error removing redirect rules:", err)
            }
        }
    }
}

// isInternalIP checks if an IP address belongs to the internal network
func isInternalIP(ip net.IP) bool {
    return internalIPNet.Contains(ip)
}

// addRedirectRule adds an iptables rule to redirect traffic to the captive portal
func addRedirectRule(clientIP string) error {
    // Check if HTTP rule already exists
    exists, err := ruleExists(clientIP, "80")
    if err != nil {
        return err
    }
    if !exists {
        cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }
    }

    // Check if HTTPS rule already exists
    exists, err = ruleExists(clientIP, "443")
    if err != nil {
        return err
    }
    if !exists {
        cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }
    }

    log.Printf("Added redirect rules for client: %s\n", clientIP)
    return nil
}

// removeRedirectRule removes the iptables redirection rules for a client
func removeRedirectRule(clientIP string) error {
    // Remove HTTP traffic redirection
    cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
    log.Println("Executing:", cmd.String())
    if err := cmd.Run(); err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            // Exit code 1 means the rule does not exist
            if exitError.ExitCode() == 1 {
                log.Printf("HTTP rule for client %s does not exist\n", clientIP)
                return nil
            }
        }
        return err
    }

    // Remove HTTPS traffic redirection
    cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
    log.Println("Executing:", cmd.String())
    if err := cmd.Run(); err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            // Exit code 1 means the rule does not exist
            if exitError.ExitCode() == 1 {
                log.Printf("HTTPS rule for client %s does not exist\n", clientIP)
                return nil
            }
        }
        return err
    }

    log.Printf("Removed redirect rules for client: %s\n", clientIP)
    return nil
}

// addRestrictedResourceRules adds iptables rules to redirect traffic to restricted resources for a client
func addRestrictedResourceRules(clientIP string, resources []string) error {
    for _, resource := range resources {
        // Redirect HTTP traffic (port 80)
        cmd := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-d", resource, "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // Redirect HTTPS traffic (port 443)
        cmd = exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-d", resource, "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }
    }
    return nil
}

// removeRestrictedResourceRules removes iptables rules for restricted resources for a client
func removeRestrictedResourceRules(clientIP string, resources []string) error {
    for _, resource := range resources {
        // Remove HTTP traffic redirection
        cmd := exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "80", "-d", resource, "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }

        // Remove HTTPS traffic redirection
        cmd = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", "443", "-d", resource, "-j", "DNAT", "--to-destination", "10.0.2.4:8080")
        log.Println("Executing:", cmd.String())
        if err := cmd.Run(); err != nil {
            return err
        }
    }
    return nil
}
func ruleExists(clientIP string, port string) (bool, error) {
    cmd := exec.Command("iptables", "-t", "nat", "-C", "PREROUTING", "-s", clientIP, "-p", "tcp", "--dport", port, "-j", "DNAT", "--to-destination", "192.168.1.1:8080")
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