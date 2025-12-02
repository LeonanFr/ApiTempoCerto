package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

type ForgotPasswordRequest struct {
	Contact string `json:"contact"`
	Type    string `json:"type"`
}

type ResetPasswordRequest struct {
	Contact     string `json:"contact"`
	Type        string `json:"type"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
}

func requestPasswordResetHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ForgotPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}

		if req.Contact == "" || (req.Type != "SMS" && req.Type != "EMAIL") {
			http.Error(w, "Contato e Tipo são obrigatórios", http.StatusBadRequest)
			return
		}

		var exists int
		var query string

		if req.Type == "SMS" {
			query = "SELECT 1 FROM users WHERE phone = $1"
		} else {
			query = "SELECT 1 FROM users WHERE email = $1"
		}

		err := db.QueryRow(query, req.Contact).Scan(&exists)
		if err == sql.ErrNoRows {
			http.Error(w, "Usuário não encontrado", http.StatusNotFound)
			return
		} else if err != nil {
			log.Printf("Erro DB Reset: %v", err)
			http.Error(w, "Erro interno", http.StatusInternalServerError)
			return
		}

		var provider NotificationProvider
		if req.Type == "SMS" {
			provider = notifier.SMS
		} else {
			provider = notifier.Email
		}

		code, _ := generateOTP()

		db.Exec("DELETE FROM verification_codes WHERE identifier = $1 AND type = $2", req.Contact, req.Type)

		_, err = db.Exec(`
			INSERT INTO verification_codes (identifier, code, type, expires_at) 
			VALUES ($1, $2, $3, NOW() + INTERVAL '15 minutes')`,
			req.Contact, code, req.Type)
		if err != nil {
			http.Error(w, "Erro ao gerar código", http.StatusInternalServerError)
			return
		}

		msg := fmt.Sprintf("Seu código para redefinir a senha: %s", code)
		err = provider.Send(req.Contact, msg)
		if err != nil {
			http.Error(w, "Erro ao enviar mensagem", http.StatusBadGateway)
			return
		}

		db.Exec("INSERT INTO otp_logs (identifier, type, purpose) VALUES ($1, $2, 'RESET_PASSWORD')", req.Contact, req.Type)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Código enviado.")
	}
}

func resetPasswordHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ResetPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON inválido", http.StatusBadRequest)
			return
		}

		if req.NewPassword == "" || len(req.NewPassword) < 6 {
			http.Error(w, "A nova senha deve ter no mínimo 6 caracteres", http.StatusBadRequest)
			return
		}

		var id int
		err := db.QueryRow(`
			SELECT id FROM verification_codes 
			WHERE identifier = $1 AND code = $2 AND type = $3 AND expires_at > NOW()`,
			req.Contact, req.Code, req.Type).Scan(&id)
		if err == sql.ErrNoRows {
			http.Error(w, "Código inválido ou expirado", http.StatusUnauthorized)
			return
		}

		newHash, err := hashPassword(req.NewPassword)
		if err != nil {
			http.Error(w, "Erro ao processar senha", http.StatusInternalServerError)
			return
		}

		var updateQuery string
		if req.Type == "SMS" {
			updateQuery = "UPDATE users SET password_hash = $1 WHERE phone = $2"
		} else {
			updateQuery = "UPDATE users SET password_hash = $1 WHERE email = $2"
		}

		res, err := db.Exec(updateQuery, newHash, req.Contact)
		if err != nil {
			log.Printf("Erro Update Senha: %v", err)
			http.Error(w, "Erro ao atualizar senha", http.StatusInternalServerError)
			return
		}

		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 0 {
			http.Error(w, "Usuário não encontrado para atualização", http.StatusNotFound)
			return
		}

		db.Exec("DELETE FROM verification_codes WHERE id = $1", id)

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "Senha alterada com sucesso. Faça login.")
	}
}
