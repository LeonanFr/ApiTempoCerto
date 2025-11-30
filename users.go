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
	Phone        string `json:"phone"`
	PasswordHash string `json:"-"`
	Password     string `json:"password,omitempty"`
}

type RegisterInput struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Password string `json:"password"`
	OtpCode  string `json:"otp_code"`
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
		return false, fmt.Errorf("hash inválido")
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
		return false, fmt.Errorf("tamanho inválido do hash")
	}

	comparisonHash := argon2.IDKey([]byte(password), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	return (subtle.ConstantTimeCompare(hash, comparisonHash) == 1), nil
}

func registerHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input RegisterInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, "Requisição inválida", http.StatusBadRequest)
			return
		}

		if input.Name == "" || input.Username == "" || input.Password == "" {
			http.Error(w, "Nome, usuário e senha são obrigatórios", http.StatusBadRequest)
			return
		}

		if input.Email == "" && input.Phone == "" {
			http.Error(w, "Email ou Telefone deve ser informado", http.StatusBadRequest)
			return
		}

		if input.OtpCode == "" {
			http.Error(w, "O código de verificação é obrigatório", http.StatusBadRequest)
			return
		}

		var identifier string
		var channelType string

		if input.Phone != "" {
			identifier = input.Phone
			channelType = "SMS"
		} else {
			identifier = input.Email
			channelType = "EMAIL"
		}

		var otpId int
		err := db.QueryRow(`
			SELECT id FROM verification_codes 
			WHERE identifier = $1 AND code = $2 AND type = $3 AND expires_at > NOW()`,
			identifier, input.OtpCode, channelType).Scan(&otpId)

		if err == sql.ErrNoRows {
			http.Error(w, "Código inválido ou expirado", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		db.Exec("DELETE FROM verification_codes WHERE id = $1", otpId)

		passwordHash, err := hashPassword(input.Password)
		if err != nil {
			http.Error(w, "Erro ao processar senha", http.StatusInternalServerError)
			return
		}

		isPhoneVerified := (channelType == "SMS")
		isEmailVerified := (channelType == "EMAIL")

		sqlStatement := `
		INSERT INTO users (name, username, email, phone, password_hash, is_phone_verified, is_email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

		var emailVal interface{} = input.Email
		if input.Email == "" {
			emailVal = nil
		}

		var phoneVal interface{} = input.Phone
		if input.Phone == "" {
			phoneVal = nil
		}

		_, err = db.Exec(sqlStatement, input.Name, input.Username, emailVal, phoneVal, passwordHash, isPhoneVerified, isEmailVerified)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				if strings.Contains(pgErr.ConstraintName, "username") {
					http.Error(w, "Nome de usuário já existe", http.StatusConflict)
					return
				}
				if strings.Contains(pgErr.ConstraintName, "email") {
					http.Error(w, "Email já cadastrado", http.StatusConflict)
					return
				}
				if strings.Contains(pgErr.ConstraintName, "phone") {
					http.Error(w, "Telefone já cadastrado", http.StatusConflict)
					return
				}
			}
			http.Error(w, "Erro ao cadastrar", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Usuário '%s' criado e verificado com sucesso", input.Username)
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
		SELECT id, name, username, COALESCE(email, ''), COALESCE(phone, ''), password_hash
		FROM users WHERE username = $1`

		err := db.QueryRow(sqlStatement, credentials.Username).Scan(
			&storedUser.ID,
			&storedUser.Name,
			&storedUser.Username,
			&storedUser.Email,
			&storedUser.Phone,
			&storedUser.PasswordHash,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
				return
			}
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		match, err := checkPasswordHash(credentials.Password, storedUser.PasswordHash)
		if err != nil || !match {
			http.Error(w, "Usuário ou senha inválidos", http.StatusUnauthorized)
			return
		}

		exp := time.Now().Add(30 * 24 * time.Hour)
		claims := &jwt.RegisteredClaims{
			Subject:   storedUser.Username,
			ExpiresAt: jwt.NewNumericDate(exp),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Erro ao gerar token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
	}
}

func meHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userContextKey).(string)
		if !ok {
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		var user User
		sqlStatement := `SELECT id, name, username, COALESCE(email, ''), COALESCE(phone, '') FROM users WHERE username = $1`

		err := db.QueryRow(sqlStatement, username).Scan(
			&user.ID,
			&user.Name,
			&user.Username,
			&user.Email,
			&user.Phone,
		)

		if err != nil {
			if err == sql.ErrNoRows {
				http.Error(w, "Usuário não encontrado", http.StatusNotFound)
				return
			}
			http.Error(w, "Erro interno", http.StatusInternalServerError)
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
			http.Error(w, "Não autorizado", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Token inválido", http.StatusUnauthorized)
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
			http.Error(w, "Token inválido", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userContextKey, username)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

type AccessRequestInput struct {
	Days int `json:"days"`
}

func requestAccessHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, ok := r.Context().Value(userContextKey).(string)
		if !ok {
			http.Error(w, "Não autorizado", http.StatusUnauthorized)
			return
		}

		var input AccessRequestInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			input.Days = 7
		}
		if input.Days <= 0 {
			input.Days = 7
		}

		var userId int
		err := db.QueryRow("SELECT id FROM users WHERE username = $1", username).Scan(&userId)
		if err != nil {
			http.Error(w, "Usuário não encontrado", http.StatusInternalServerError)
			return
		}

		var count int
		err = db.QueryRow("SELECT COUNT(*) FROM access_requests WHERE user_id = $1 AND status = 'PENDING'", userId).Scan(&count)
		if err != nil {
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		if count > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"message": "Você já possui uma solicitação em análise."})
			return
		}

		_, err = db.Exec("INSERT INTO access_requests (user_id, status, requested_days) VALUES ($1, 'PENDING', $2)", userId, input.Days)
		if err != nil {
			if strings.Contains(err.Error(), "idx_unique_pending_request") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"message": "Você já possui uma solicitação em análise."})
				return
			}
			http.Error(w, "Erro ao processar solicitação", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Solicitação de %d dias enviada com sucesso", input.Days)
	}
}
