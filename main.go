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

	fmt.Println("Servidor iniciado na porta 8080")
	fmt.Println("Endpoints disponíveis:")
	fmt.Println("  - POST /register")
	fmt.Println("  - POST /login")
	fmt.Println("  - GET /logs/{nome_da_estacao}/latest (Protegido)")
	fmt.Println("  - GET /logs/{nome_da_estacao}?date=YYYY-MM-DD (Protegido)")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
