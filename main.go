package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// Database connection string
const (
	host     = "localhost"
	port     = 5432
	user     = "app_user"
	password = "minorproject"
	dbname   = "captive_portal"
)

var db *sql.DB
var mutex = &sync.RWMutex{}

// User represents an authenticated user with a role
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// Session represents an authenticated session
type Session struct {
	IPAddress  string    `json:"ip_address"`
	Role       string    `json:"role"`
	Username   string    `json:"username"`
	LoginTime  time.Time `json:"login_time"`
	Expiration time.Time `json:"expiration"`
}
type Role struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Resource represents a resource with an IP address
type Resource struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	IPAddress string `json:"ip_address"`
}

// Global state
var activeSessions = map[string]Session{} // IP address -> Session

func main() {
	// Connect to the database
	psqlInfo := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)
	var err error
	db, err = sql.Open("postgres", psqlInfo)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Test the database connection
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// Serve static files
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	// Routes
	http.HandleFunc("/", handleRoot)
	http.HandleFunc("/api/login", handleLogin)
	http.HandleFunc("/api/logout", handleLogout)
	http.HandleFunc("/api/check", handleAccessCheck)
	http.HandleFunc("/api/roles", handleGetRoles)
	http.HandleFunc("/api/resources", handleGetResources)
	http.HandleFunc("/api/addUser", handleAddUser)
	http.HandleFunc("/api/addRole", handleAddRole)
	http.HandleFunc("/api/addResource", handleAddResource)
	http.HandleFunc("/api/assignResource", handleAssignResource)
	http.HandleFunc("/api/activeSessions", handleActiveSessions)
	// Start HTTP server
	fmt.Println("Starting captive portal server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handleRoot redirects to login page for unauthenticated users
func handleRoot(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	mutex.RLock()
	session, exists := activeSessions[ip]
	mutex.RUnlock()

	if !exists || time.Now().After(session.Expiration) {
		// Not authenticated, serve login page
		http.ServeFile(w, r, "./static/login.html")
		return
	}

	// Already authenticated, serve welcome page
	http.ServeFile(w, r, "./static/dashboard.html")
}

// handleLogin processes login requests
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var loginData struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	err := json.NewDecoder(r.Body).Decode(&loginData)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify credentials
	var user User
	var roleName string
	err = db.QueryRow("SELECT username, password, roles.name FROM users JOIN roles ON users.role = roles.name WHERE username = $1", loginData.Username).Scan(&user.Username, &user.Password, &roleName)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		fmt.Println(err)
		http.Error(w, "Database error ", http.StatusInternalServerError)
		return
		
	}

	if user.Password != loginData.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Create session
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	session := Session{
		IPAddress:  ip,
		Role:       roleName,
		Username:   user.Username,
		LoginTime:  time.Now(),
		Expiration: time.Now().Add(24 * time.Hour), // 24-hour session
	}

	mutex.Lock()
	activeSessions[ip] = session
	mutex.Unlock()

	// Return success with role
	response := map[string]string{
		"status": "success",
		"role":   roleName,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleLogout handles logout requests
func handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	mutex.Lock()
	delete(activeSessions, ip)
	mutex.Unlock()

	response := map[string]string{"status": "success"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// handleAccessCheck checks if a user has access to a resource
func handleAccessCheck(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)

	mutex.RLock()
	session, exists := activeSessions[ip]
	mutex.RUnlock()

	if !exists || time.Now().After(session.Expiration) {
		http.Error(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	// Fetch restricted accessible to the user's role
	var resources []Resource
	rows, err := db.Query(`
		SELECT r.id, r.name, r.ip_address 
		FROM resources r
		JOIN role_resources rr ON r.name = rr.resource
		JOIN roles ON rr.role = roles.name
		WHERE roles.name = $1
	`, session.Role)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var resource Resource
		if err := rows.Scan(&resource.ID, &resource.Name, &resource.IPAddress); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		resources = append(resources, resource)
	}

	// Return session and resource data
	response := map[string]interface{}{
		"username":   session.Username,
		"role":       session.Role,
		"ip":         ip,
		"loginTime":  session.LoginTime,
		"expiration": session.Expiration,
		"resources":  resources,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Helper function to check if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Function to integrate with your deep packet inspection
// Call this when you detect a new VM connection
func redirectNewDevice(ipAddress string) {
	// You would implement this according to your network setup
	// For example, using iptables to redirect HTTP traffic to your portal

	// Example (pseudo-code):
	// exec.Command("iptables", "-t", "nat", "-A", "PREROUTING", "-s", ipAddress,
	//             "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-port", "8080").Run()

	fmt.Printf("Redirecting new device: %s to captive portal\n", ipAddress)
}

// Function to add a user to the system
func handleAddUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newUser struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role   string    `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newUser); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)",
		newUser.Username, newUser.Password, newUser.Role)
	if err != nil {
		fmt.Println(err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleAddRole adds a new role
func handleAddRole(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newRole struct {
		Name string `json:"name"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newRole); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO roles (name) VALUES ($1)", newRole.Name)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// handleAddResource adds a new resource
func handleAddResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var newResource struct {
		Name      string `json:"name"`
		IPAddress string `json:"ip_address"`
	}

	if err := json.NewDecoder(r.Body).Decode(&newResource); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO resources (name, ip_address) VALUES ($1, $2)",
		newResource.Name, newResource.IPAddress)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// Function to get the role for an IP address
func handleGetRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name FROM roles")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Name); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		roles = append(roles, role)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(roles)
}
func handleGetResources(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, name, ip_address FROM resources")
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var resources []Resource
	for rows.Next() {
		var resource Resource
		if err := rows.Scan(&resource.ID, &resource.Name, &resource.IPAddress); err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}
		resources = append(resources, resource)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resources)
}
func handleAssignResource(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var assignment struct {
		Role     string `json:"role"`
		Resource string `json:"resource"`
	}

	if err := json.NewDecoder(r.Body).Decode(&assignment); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO role_resources (role, resource) VALUES ($1, $2)",
		assignment.Role, assignment.Resource)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func handleActiveSessions(w http.ResponseWriter, r *http.Request) {
	mutex.RLock()
	defer mutex.RUnlock()

	sessions := make(map[string]bool)
	for ip, session := range activeSessions {
		sessions[ip] = time.Now().Before(session.Expiration)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sessions)
}

