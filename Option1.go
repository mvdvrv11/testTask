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
	// Секретный ключ для подписания JWT-токена
	secretKey = []byte("your-secret-key")
)

type User struct {
	ID       bson.ObjectId `bson:"_id,omitempty"`
	Username string        `bson:"username"`
	Password string        `bson:"password"`
}

func main() {
	// Инициализация сеанса MongoDB
	session, err := mgo.Dial("mongodb://localhost")
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	// Создание нового маршрута
	router := mux.NewRouter()
// Выдача access & refresh токенов
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		// Get the username and password from the request parameters
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Поиск пользователя по username в ДБ
		c := session.DB("your-database-name").C("users")
		var user User
		err := c.Find(bson.M{"username": username}).One(&user)
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Сравнение пароля с хэшем в ДЬ
		err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
		if err != nil {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		// Создание нового JWT токена
		token := jwt.New(jwt.SigningMethodHS512)
		claims := token.Claims.(jwt.MapClaims)
		claims["username"] = user.Username
		claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
// Подписание токена секретным ключем
		tokenString, err := token.SignedString(secretKey)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// Генерация refresh токена
		refreshToken := generateRefreshToken()

		// Возврат refresh & access токена клиенту
		response := map[string]string{
			"access_token":  tokenString,
			"refresh_token": refreshToken,
		}
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Маршрут обновления access токена
	router.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		// Получение refresh токена из параметров запроса
		refreshToken := r.FormValue("refresh_token")
		
// Клиент получает новый access токен
		response := map[string]string{
			"access_token": newAccessToken,
		}
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Запуск HTTP сервера
	log.Fatal(http.ListenAndServe(":8080", router))
}

func generateRefreshToken() string {
	// Генерация рандомного refresh токена
	// Для генерации уникального токена можно использовать uuid
	refreshToken := "your-refresh-token"
	return refreshToken
}
