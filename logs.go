package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type StationConfig struct {
	TableName  string
	DateColumn string
	Columns    []string
}

var stationConfigs = map[string]StationConfig{
	"soure": {
		TableName:  "datalogger_raw",
		DateColumn: "date",
		Columns: []string{"date", "air_temperature", "air_humid", "air_pressure", "precipitation",
			"wind_speed_min", "wind_speed_max", "wind_speed_mean", "wind_direction",
			"water_level", "water_temperature", "solar_radiance"},
	},
	"curuca": {
		TableName:  "datalogger_curuca",
		DateColumn: "date",
		Columns:    []string{"date", "temperature", "salinity", "pressure"},
	},
}

type ErrorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func logsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(pathParts) < 2 {
			http.Error(w, "URL inválida", http.StatusBadRequest)
			return
		}

		stationName := pathParts[1]
		config, ok := stationConfigs[stationName]
		if !ok {
			http.Error(w, fmt.Sprintf("Estação '%s' não configurada", stationName), http.StatusNotFound)
			return
		}

		var lastDataDate time.Time

		lastDateQuery := fmt.Sprintf("SELECT MAX(%s) FROM %s", config.DateColumn, config.TableName)
		if config.TableName == "datalogger_raw" && stationName == "soure" {
			lastDateQuery += " WHERE station_id = 2"
		}

		err := db.QueryRow(lastDateQuery).Scan(&lastDataDate)
		if err != nil {
			lastDataDate = time.Now().In(location)
		} else {
			lastDataDate = lastDataDate.In(location)
		}

		limitDate := lastDataDate.AddDate(0, 0, -7)
		isRestricted := false

		columnsStr := strings.Join(config.Columns, ", ")
		query := fmt.Sprintf("SELECT %s FROM %s", columnsStr, config.TableName)

		args := []interface{}{}
		argCounter := 1

		if config.TableName == "datalogger_raw" {
			if stationName == "soure" {
				query += fmt.Sprintf(" WHERE station_id = $%d", argCounter)
				args = append(args, 2)
				argCounter++
			}
		}

		isLatestRequest := len(pathParts) > 2 && pathParts[2] == "latest"
		dateQuery := r.URL.Query().Get("date")
		startDateQuery := r.URL.Query().Get("startDate")
		endDateQuery := r.URL.Query().Get("endDate")

		if isLatestRequest {
			query += fmt.Sprintf(" ORDER BY %s DESC LIMIT 1", config.DateColumn)
		} else if startDateQuery != "" && endDateQuery != "" {
			startDate, err1 := time.ParseInLocation("2006-01-02", startDateQuery, location)
			endDate, err2 := time.ParseInLocation("2006-01-02", endDateQuery, location)
			if err1 != nil || err2 != nil {
				http.Error(w, "Formato de data inválido", http.StatusBadRequest)
				return
			}

			if startDate.Before(limitDate) {
				isRestricted = true
			}

			endDate = endDate.Add(24 * time.Hour)

			if strings.Contains(query, "WHERE") {
				query += fmt.Sprintf(" AND %s >= $%d AND %s < $%d", config.DateColumn, argCounter, config.DateColumn, argCounter+1)
			} else {
				query += fmt.Sprintf(" WHERE %s >= $%d AND %s < $%d", config.DateColumn, argCounter, config.DateColumn, argCounter+1)
			}

			args = append(args, startDate, endDate)
			query += fmt.Sprintf(" ORDER BY %s ASC", config.DateColumn)

		} else if dateQuery != "" {
			startDate, err := time.ParseInLocation("2006-01-02", dateQuery, location)
			if err != nil {
				http.Error(w, "Formato de data inválido", http.StatusBadRequest)
				return
			}

			if startDate.Before(limitDate) {
				isRestricted = true
			}

			endDate := startDate.Add(24 * time.Hour)

			if strings.Contains(query, "WHERE") {
				query += fmt.Sprintf(" AND %s >= $%d AND %s < $%d", config.DateColumn, argCounter, config.DateColumn, argCounter+1)
			} else {
				query += fmt.Sprintf(" WHERE %s >= $%d AND %s < $%d", config.DateColumn, argCounter, config.DateColumn, argCounter+1)
			}

			args = append(args, startDate, endDate)
			query += fmt.Sprintf(" ORDER BY %s ASC", config.DateColumn)

		} else {
			http.Error(w, "Requisição inválida", http.StatusBadRequest)
			return
		}

		if isRestricted {
			username, ok := r.Context().Value(userContextKey).(string)
			if ok {
				var accessUntil sql.NullTime
				err := db.QueryRow("SELECT history_access_until FROM users WHERE username = $1", username).
					Scan(&accessUntil)

				if err == nil && accessUntil.Valid && accessUntil.Time.After(time.Now()) {
					isRestricted = false
				}
			}
		}

		if isRestricted {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{
				Code:    "DATA_RESTRICTED",
				Message: "Dados antigos arquivados (regra de 7 dias do último registro).",
			})
			return
		}

		rows, err := db.Query(query, args...)
		if err != nil {
			http.Error(w, "Erro ao buscar dados", http.StatusInternalServerError)
			log.Printf("Query Error: %v", err)
			return
		}
		defer rows.Close()

		results, err := scanToMap(rows)
		if err != nil {
			http.Error(w, "Erro ao processar dados", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if isLatestRequest {
			if len(results) == 0 {
				json.NewEncoder(w).Encode(nil)
			} else {
				json.NewEncoder(w).Encode(results[0])
			}
		} else {
			json.NewEncoder(w).Encode(results)
		}
	}
}

func scanToMap(rows *sql.Rows) ([]map[string]interface{}, error) {
	columns, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	results := make([]map[string]interface{}, 0)

	for rows.Next() {
		values := make([]interface{}, len(columns))
		valuePtrs := make([]interface{}, len(columns))
		for i := range columns {
			valuePtrs[i] = &values[i]
		}

		if err := rows.Scan(valuePtrs...); err != nil {
			return nil, err
		}

		rowData := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]

			if t, ok := val.(time.Time); ok {
				rowData[col] = t.In(location).Format(time.RFC3339)
			} else if b, ok := val.([]byte); ok {
				rowData[col] = string(b)
			} else {
				rowData[col] = val
			}
		}
		results = append(results, rowData)
	}

	return results, rows.Err()
}
