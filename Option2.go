package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var (
	accessSecret = []byte("access-secret-key")
	refreshSecret = []byte("refresh-secret-key")
)

type User struct {
	ID       string `bson:"_id"`
	Username string `bson:"username"`
	Password string `bson:"password"`
}

func main() {
	r := gin.Default()

	// Установка маршрутов
	r.POST("/get_tokens", GetTokens)
	r.POST("/refresh_token", RefreshToken)

	// Запуск сервера
	r.Run(":8080")
}

func GetTokens(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Здесь нужно добавить код для проверки учетных данных в базе данных (MongoDB)

	// В случае успешной аутентификации, создаем Access и Refresh токены
	accessToken, err := createAccessToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating access token"})
		return
	}

	refreshToken, err := createRefreshToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken})
}

func RefreshToken(c *gin.Context) {
	refreshToken := c.PostForm("refresh_token")

	// Здесь нужно добавить код для проверки Refresh токена в базе данных (MongoDB)

	// В случае успешной проверки, создаем новый Access токен
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return refreshSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	username := claims["username"].(string)

	accessToken, err := createAccessToken(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error creating access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken})
}

func createAccessToken(username string) (string, error) {
	// Создание Access токена
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Minute * 15).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	accessToken, err := token.SignedString(accessSecret)
	if err != nil {
		return "", err
	}
	return accessToken, nil
}

func createRefreshToken(username string) (string, error) {
	// Создание Refresh токена
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	refreshToken := base64.StdEncoding.EncodeToString(token)

	// Хеширование Refresh токена перед сохранением в базу данных
	hashedRefreshToken, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	// Здесь нужно добавить код для сохранения хеша Refresh токена в базу данных (MongoDB)

	return refreshToken, nil
}
