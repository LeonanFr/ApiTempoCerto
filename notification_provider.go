package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type NotificationProvider interface {
	Send(to string, message string) error
}

type TwilioProvider struct {
	AccountSID string
	AuthToken  string
	FromPhone  string
}

func (t *TwilioProvider) Send(to string, message string) error {
	apiURL := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", t.AccountSID)

	data := url.Values{}
	data.Set("To", to)
	data.Set("From", t.FromPhone)
	data.Set("Body", message)

	req, err := http.NewRequest("POST", apiURL, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}

	req.SetBasicAuth(t.AccountSID, t.AuthToken)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	var errorResp map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&errorResp)
	return fmt.Errorf("erro Twilio (Status %d): %v", resp.StatusCode, errorResp["message"])
}

type SendGridProvider struct {
	APIKey      string
	FromAddress string
}

func (s *SendGridProvider) Send(to string, message string) error {
	fmt.Printf("[MOCK SENDGRID] Enviando Email para %s: %s\n", to, message)
	return nil
}

type NotificationService struct {
	SMS   NotificationProvider
	Email NotificationProvider
}

var notifier NotificationService
