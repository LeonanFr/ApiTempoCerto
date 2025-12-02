package main

import (
	"bytes"
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

type SGData struct {
	Personalizations []SGPersonalization `json:"personalizations"`
	From             SGContact           `json:"from"`
	Content          []SGContent         `json:"content"`
}
type SGPersonalization struct {
	To      []SGContact `json:"to"`
	Subject string      `json:"subject"`
}
type SGContact struct {
	Email string `json:"email"`
}
type SGContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SendGridProvider struct {
	APIKey      string
	FromAddress string
}

func (s *SendGridProvider) Send(to string, message string) error {
	url := "https://api.sendgrid.com/v3/mail/send"

	payload := SGData{
		Personalizations: []SGPersonalization{
			{
				To:      []SGContact{{Email: to}},
				Subject: "Seu código de verificação TempoCerto",
			},
		},
		From: SGContact{Email: s.FromAddress},
		Content: []SGContent{
			{
				Type:  "text/plain",
				Value: message,
			},
		},
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", "Bearer "+s.APIKey)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	return fmt.Errorf("erro SendGrid (Status %d)", resp.StatusCode)
}

type NotificationService struct {
	SMS   NotificationProvider
	Email NotificationProvider
}

var notifier NotificationService
