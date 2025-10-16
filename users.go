package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgconn"
	"golang.org/x/crypto/argon2"
)

type contextKey string

const userContextKey = contextKey("username")

type argonParams struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var params = &argonParams{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

type User struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	Password     string `json:"password,omitempty"`
}

func hashPassword(password string) (string, error) {
	salt := make([]byte, params.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf("%s:%s", b64Salt, b64Hash), nil
}

func checkPasswordHash(password, storedHash string) (bool, error) {
	parts := strings.Split(storedHash, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("hash armazenado em formato inválido")
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	if uint32(len(hash)) != params.keyLength {
		return false, fmt.Errorf("hash com comprimento inesperado")
	}

	comparisonHash := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	return (subtle.ConstantTimeCompare(hash, comparisonHash) == 1), nil
}

func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var user User
		if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
			http.Error(w, "Requisição inválida", http.StatusBadRequest)
			return
		}

		if user.Name == "" || user.Username == "" || user.Email == "" || user.Password == "" {
			http.Error(w, "Nome, usuário, email e senha são obrigatórios", http.StatusBadRequest)
			return
		}

		passwordHash, err := hashPassword(user.Password)
		if err != nil {
			log.Printf("Erro ao gerar hash: %v", err)
			http.Error(w, "Erro ao processar senha", http.StatusInternalServerError)
			return
		}

		sqlStatement := `
		INSERT INTO users (name, username, email, password_hash)
		VALUES ($1, $2, $3, $4)`

		_, err = db.Exec(sqlStatement, user.Name, user.Username, user.Email, passwordHash)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if pgErr.ConstraintName == "users_username_key" {
					http.Error(w, "Nome de usuário já existe", http.StatusConflict)
					return
				}
				if pgErr.ConstraintName == "users_email_key" {
					http.Error(w, "Email já cadastrado", http.StatusConflict)
					return
				}
			}
			log.Printf("Erro ao inserir usuário: %v", err)
			http.Error(w, "Erro ao cadastrar usuário", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Usuário '%s' criado com sucesso", user.Username)
	}
}

func loginHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var credentials User
		if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
			http.Error(w, "Requisição inválida", http.StatusBadRequest)
			return
		}

		var storedUser User
		sqlStatement := `
		SELECT id, name, username, email, password_hash
		FROM users WHERE username = $1`

		err := db.QueryRow(sqlStatement, credentials.Username).Scan(
			&storedUser.ID,
			&storedUser.Name,
			&storedUser.Username,
			&storedUser.Email,
			&storedUser.PasswordHash,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Erro interno do servidor", http.StatusInternalServerError)
			return
		}

		match, err := checkPasswordHash(credentials.Password, storedUser.PasswordHash)
		if err != nil {
			log.Printf("Erro ao verificar hash: %v", err)
			http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
			return
		}

		if !match {
			http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
			return
		}

		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &jwt.RegisteredClaims{
			Subject:   storedUser.Username,
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Erro ao gerar token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"token": tokenString,
		})
	}
}

func meHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userContextKey).(string)
		if !ok {
			http.Error(w, "Erro ao ler usuário do contexto", http.StatusInternalServerError)
			return
		}

		var user User
		sqlStatement := `SELECT id, name, username, email FROM users WHERE username = $1`

		err := db.QueryRow(sqlStatement, username).Scan(
			&user.ID,
			&user.Name,
			&user.Username,
			&user.Email,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Usuário não encontrado", http.StatusNotFound)
				return
			}
			http.Error(w, "Erro ao buscar usuário", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Cabeçalho de autorização ausente", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Formato do token inválido", http.StatusUnauthorized)
			return
		}

		claims := &jwt.RegisteredClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Token inválido", http.StatusUnauthorized)
			return
		}

		username, err := claims.GetSubject()
		if err != nil {
			http.Error(w, "Token inválido (sem subject)", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, username)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
