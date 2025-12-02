package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"
)

type SendOTPRequest struct {
	Contact string `json:"contact"`
	Type    string `json:"type"`
	Purpose string `json:"purpose"`
}

type VerifyOTPRequest struct {
	Contact string `json:"contact"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func generateOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()+100000), nil
}

func sendOTPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SendOTPRequest

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("ERRO DECODE JSON: %v", err)

			http.Error(w, fmt.Sprintf("JSON inválido: %v", err), http.StatusBadRequest)
			return
		}

		if req.Contact == "" || (req.Type != "SMS" && req.Type != "EMAIL") {
			http.Error(w, "Campos 'contact' e 'type' são obrigatórios", http.StatusBadRequest)
			return
		}
		if req.Purpose == "" {
			req.Purpose = "REGISTER"
		}

		if req.Purpose == "REGISTER" {
			var exists int

			query := "SELECT 1 FROM users where phone=$1 OR email =$1"
			err := db.QueryRow(query, req.Contact).Scan(&exists)

			if err == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]string{"message": "Este contato já possui cadastro. Faça login."})
				return
			} else if err != sql.ErrNoRows {
				log.Printf("Erro DB User Check: %v", err)
				http.Error(w, "Erro interno", http.StatusInternalServerError)
				return
			}

		}

		var lastSent time.Time
		err := db.QueryRow("SELECT sent_at FROM otp_logs WHERE identifier=$1 ORDER BY id DESC LIMIT 1", req.Contact).Scan(&lastSent)
		if err == nil {
			if time.Since(lastSent) < 60*time.Second {
				wait := 60 - int(time.Since(lastSent).Seconds())
				http.Error(w, fmt.Sprintf("Aguarde %d segundos para reenviar.", wait), http.StatusTooManyRequests)
				return
			}
		}

		var dailyCount int
		err = db.QueryRow("SELECT COUNT(*) FROM otp_logs WHERE identifier = $1 AND sent_at > NOW() - INTERVAL '24 hours'", req.Contact).Scan(&dailyCount)
		if err == nil && dailyCount >= 3 {
			http.Error(w, "Limite diário de verificações excedido. Tente amanhã.", http.StatusTooManyRequests)
			return
		}

		var provider NotificationProvider
		if req.Type == "SMS" {
			provider = notifier.SMS
		} else {
			provider = notifier.Email
		}

		if provider == nil {
			http.Error(w, "Serviço de notificação não configurado", http.StatusInternalServerError)
			return
		}

		code, err := generateOTP()
		if err != nil {
			http.Error(w, "Erro ao gerar código", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("DELETE FROM verification_codes WHERE identifier = $1 AND type = $2", req.Contact, req.Type)
		if err != nil {
			log.Printf("Erro limpeza OTP: %v", err)
		}

		_, err = db.Exec(`
    INSERT INTO verification_codes (identifier, code, type, expires_at) 
    VALUES ($1, $2, $3, NOW() + INTERVAL '15 minutes')`,
			req.Contact, code, req.Type)
		if err != nil {
			http.Error(w, "Erro ao processar", http.StatusInternalServerError)
			return
		}

		msg := fmt.Sprintf("Seu codigo de verificacao TempoCerto e: %s", code)
		err = provider.Send(req.Contact, msg)
		if err != nil {
			http.Error(w, "Falha ao enviar código", http.StatusBadGateway)
			return
		}
		db.Exec("INSERT INTO otp_logs (identifier, type, purpose) VALUES ($1, $2, $3)", req.Contact, req.Type, req.Purpose)
		
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Código enviado com sucesso")
	}
}

func verifyOTPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req VerifyOTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}

		var id int
		err := db.QueryRow(
			"SELECT id FROM verification_codes WHERE identifier = $1 AND code = $2 AND type = $3 AND expires_at > NOW()",
			req.Contact, req.Code, req.Type,
		).Scan(&id)

		if err == sql.ErrNoRows {
			http.Error(w, "Código inválido ou expirado", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		db.Exec("DELETE FROM verification_codes WHERE id = $1", id)

		if req.Type == "SMS" {
			db.Exec("UPDATE users SET is_phone_verified = TRUE WHERE phone = $1", req.Contact)
		} else {
			db.Exec("UPDATE users SET is_email_verified = TRUE WHERE email = $1", req.Contact)
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Verificado com sucesso")
	}
}
