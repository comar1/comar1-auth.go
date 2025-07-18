package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// User represents the user model
type User struct {
	Username string `json:"username"`
	UUID     string `json:"uuid"`
	Hashed   string `json:"hashed"`
	Salt     string `json:"salt"`
}

// In-memory storage (replace with database in production)
var (
	users     = make(map[string]User)
	usersLock sync.Mutex
	csrfCache = make(map[string]string)
	cacheLock sync.Mutex
)

// Helper function to generate salt/UUID
func generateSalt() string {
	bytes := make([]byte, 18)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal("Error generating random bytes:", err)
	}

	parts := []string{
		hex.EncodeToString(bytes[0:4]),
		hex.EncodeToString(bytes[4:6]),
		hex.EncodeToString(bytes[6:8]),
		hex.EncodeToString(bytes[8:10]),
		hex.EncodeToString(bytes[10:18]),
	}

	return strings.Join(parts, "-")
}

// JSON response helper
func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Handlers
func testHandler(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Test successful!",
		"message":        "You have been authenticated successfully.",
		"data":           "Test data",
	})
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Register successful!",
		"message":        "Account registered: " + username,
		"data": map[string]string{
			"username": username,
			"password": password,
		},
	})
}

func getHashHandler(w http.ResponseWriter, r *http.Request) {
	salt := generateSalt()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Salt generation successful!",
		"message":        "Generated salt: " + salt,
		"data":           salt,
	})
}

func getSaltedPasswordHandler(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	salt := r.FormValue("salt")
	newHash := password + salt

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Password salt successful!",
		"message":        "Generated password: " + newHash,
		"data":           newHash,
	})
}

func getHashedPasswordHandler(w http.ResponseWriter, r *http.Request) {
	salted := r.FormValue("salted")
	hash := sha256.Sum256([]byte(salted))
	hashedPassword := hex.EncodeToString(hash[:])

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Password hash successful!",
		"message":        "Generated password: " + hashedPassword,
		"data":           hashedPassword,
	})
}

func generateUserIDHandler(w http.ResponseWriter, r *http.Request) {
	uuid := generateSalt()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "UUID generate successful!",
		"message":        "Generated username: " + uuid,
		"data":           uuid,
	})
}

func accountHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var data User
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	usersLock.Lock()
	users[data.Username] = data
	usersLock.Unlock()

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"server_message": "Create User successful!",
		"message":        "Generated username: " + data.Username,
	})
}

func checkCsrfHandler(w http.ResponseWriter, r *http.Request) {
	csrfToken := r.Header.Get("X-CSRF-TOKEN")
	cacheLock.Lock()
	storedToken := csrfCache["csrf_token"]
	cacheLock.Unlock()

	if csrfToken != storedToken {
		jsonResponse(w, http.StatusUnauthorized, map[string]string{
			"error": "Invalid CSRF token",
		})
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{
		"message": "CSRF token is valid",
	})
}

func main() {
	// Initialize CSRF token
	cacheLock.Lock()
	csrfCache["csrf_token"] = generateSalt()
	cacheLock.Unlock()

	// Set up routes
	http.HandleFunc("/test", testHandler)
	http.HandleFunc("/register", registerHandler)
	http.HandleFunc("/get-hash", getHashHandler)
	http.HandleFunc("/get-salted-password", getSaltedPasswordHandler)
	http.HandleFunc("/get-hashed-password", getHashedPasswordHandler)
	http.HandleFunc("/generate-user-id", generateUserIDHandler)
	http.HandleFunc("/account", accountHandler)
	http.HandleFunc("/check-csrf", checkCsrfHandler)

	// Start server
	port := ":8080"
	fmt.Printf("Server starting on %s...\n", port)
	server := &http.Server{
		Addr:         port,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}