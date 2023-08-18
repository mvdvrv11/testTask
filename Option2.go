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

	// Запуск сервака
	r.Run(":8080")
}

func GetTokens(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Нужен код для проверки учетных данных в базе данных (MongoDB) сгенерировал пример кода с помощью ИИ.

// Подключение к базе данных
const url = 'mongodb://localhost:27017';
const dbName = 'mydb';

MongoClient.connect(url, { useUnifiedTopology: true }, (err, client) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    return;
  }

  const db = client.db(dbName);
  const collection = db.collection('users');

  // Проверка наличия учетных данных
  collection.find({ username: 'example' }).toArray((err, result) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err);
      return;
    }

    if (result.length > 0) {
      console.log('Учетные данные найдены');
    } else {
      console.log('Учетные данные не найдены');
    }

    // Закрытие подключения к базе данных
    client.close();
  });
});

	// При успешной аутентификации, создаем Access и Refresh токены
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

	// нужен код для проверки Refresh токена в базе данных (MongoDB). Тоже сгенерировал с помощью ИИ
	const MongoClient = require('mongodb').MongoClient;

// Подключение к базе данных
const url = 'mongodb://localhost:27017';
const dbName = 'mydb';

MongoClient.connect(url, { useUnifiedTopology: true }, (err, client) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    return;
  }

  const db = client.db(dbName);
  const collection = db.collection('tokens');

  // Проверка наличия Refresh токена
  collection.find({ refreshToken: 'example' }).toArray((err, result) => {
    if (err) {
      console.error('Ошибка при выполнении запроса:', err);
      return;
    }

    if (result.length > 0) {
      console.log('Refresh токен найден');
    } else {
      console.log('Refresh токен не найден');
    }

    // Закрытие подключения к базе данных
    client.close();
  });
});

	// При успешной проверке, создаем новый Access токен
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

	//нужен код для сохранения хеша Refresh токена в базу данных (MongoDB). Ну и в 3й раз тоже ИИ.
const MongoClient = require('mongodb').MongoClient;
const bcrypt = require('bcrypt');

// Подключение к базе данных
const url = 'mongodb://localhost:27017';
const dbName = 'mydb';

MongoClient.connect(url, { useUnifiedTopology: true }, (err, client) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err);
    return;
  }

  const db = client.db(dbName);
  const collection = db.collection('tokens');

  // Хеширование Refresh токена
  const refreshToken = 'example';
  bcrypt.hash(refreshToken, 10, (err, hash) => {
    if (err) {
      console.error('Ошибка при хешировании токена:', err);
      return;
    }

    // Сохранение хеша Refresh токена в базе данных
    collection.insertOne({ refreshToken: hash }, (err, result) => {
      if (err) {
        console.error('Ошибка при сохранении хеша токена:', err);
	return refreshToken, nil
} return;
      }

      console.log('Хеш Refresh токена успешно сохранен в базе данных');

      // Закрытие подключения к базе данных
      client.close();
    });
  });
});
