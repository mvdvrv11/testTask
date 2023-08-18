package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	// Secret key for JWT token signing
	secretKey = []byte("your-secret-key")
)

type User struct {
	ID       bson.ObjectId `bson:"_id,omitempty"`
	Username string        `bson:"username"`
	Password string        `bson:"password"`
}

func main() {
	// Initialize the MongoDB session
	session, err := mgo.Dial("mongodb://localhost")
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// Create a new router
	router := mux.NewRouter()
// Route to issue access and refresh tokens
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Get the username and password from the request parameters
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Find the user in the database based on the username
		c := session.DB("your-database-name").C("users")
		var user User
		err := c.Find(bson.M{"username": username}).One(&user)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Compare the provided password with the hashed password from the database
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Create a new JWT token
		token := jwt.New(jwt.SigningMethodHS512)
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
// Sign the token with the secret key
		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Generate a refresh token
		refreshToken := generateRefreshToken()

		// Store the relationship between the access token and refresh token in the database
		// You can use a separate collection in MongoDB to store this information

		// Return the access and refresh tokens to the client
		response := map[string]string{
			"access_token":  tokenString,
			"refresh_token": refreshToken,
		}
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Route to refresh the access token
	router.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		// Get the refresh token from the request parameters
		refreshToken := r.FormValue("refresh_token")

		// Check if the refresh token is valid and retrieve the associated access token
		// You can query the database to check if the refresh token exists and retrieve the associated access token

		// Generate a new access token using the retrieved access token
// Return the new access token to the client
		response := map[string]string{
			"access_token": newAccessToken,
		}
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Start the HTTP server
	log.Fatal(http.ListenAndServe(":8080", router))
}

func generateRefreshToken() string {
	// Generate a random refresh token
	// You can use a library like uuid to generate a unique refresh token
	refreshToken := "your-refresh-token"
	return refreshToken
}
