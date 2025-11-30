package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v4/stdlib"
)

var location, errLocation = time.LoadLocation("America/Sao_Paulo")
var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY"))

func main() {
	if errLocation != nil {
		log.Fatalf("Não foi possível carregar a informação de fuso horário: %v", errLocation)
	}

	if len(jwtKey) == 0 {
		log.Fatal("A variável de ambiente JWT_SECRET_KEY não foi definida")
	}

	twilioSID := os.Getenv("TWILIO_ACCOUNT_SID")
	twilioToken := os.Getenv("TWILIO_AUTH_TOKEN")
	twilioFrom := os.Getenv("TWILIO_PHONE_NUMBER")

	if twilioSID != "" && twilioToken != "" {
		notifier.SMS = &TwilioProvider{
			AccountSID: twilioSID,
			AuthToken:  twilioToken,
			FromPhone:  twilioFrom,
		}
		fmt.Println("Serviço de SMS (Twilio) ativado.")
	} else {
		fmt.Println("AVISO: Variáveis do Twilio não encontradas. SMS não funcionará.")
	}

	notifier.Email = &SendGridProvider{
		APIKey:      os.Getenv("SENDGRID_API_KEY"),
		FromAddress: "no-reply@tempocerto.com",
	}

	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		log.Fatal("A variável de ambiente DATABASE_URL não foi definida")
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		log.Fatalf("Não foi possível conectar ao banco de dados: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("Não foi possível verificar a conexão com o banco de dados: %v", err)
	}
	fmt.Println("Conexão com o PostgreSQL estabelecida com sucesso!")

	http.HandleFunc("/register", registerHandler(db))
	http.HandleFunc("/login", loginHandler(db))
	http.Handle("/request-access", authMiddleware(requestAccessHandler(db)))
	http.Handle("/logs/", authMiddleware(logsHandler(db)))
	http.Handle("/me", authMiddleware(meHandler(db)))

	http.HandleFunc("/auth/send-otp", sendOTPHandler(db))
	http.HandleFunc("/auth/verify-otp", verifyOTPHandler(db))

	fmt.Println("Servidor iniciado na porta 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
