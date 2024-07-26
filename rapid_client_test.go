package gorapid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Mock token response
var mockTokenResponse = `{
	"access_token": "mockAccessToken",
	"expires_in": 3600,
	"token_type": "Bearer",
	"refresh_token": "mockRefreshToken"
}`

// Helper function to set environment variables
func setEnv(key, value string) {
	err := os.Setenv(key, value)
	if err != nil {
		panic(err)
	}
}

// Helper function to unset environment variables
func unsetEnv(key string) {
	err := os.Unsetenv(key)
	if err != nil {
		panic(err)
	}
}

// Test for NewRapidClient function
func TestNewRapidClient(t *testing.T) {
	setEnv("RAPID_BASE_URL", "http://mockapi.com")
	setEnv("RAPID_KEY", "mockKey")
	setEnv("RAPID_SECRET", "mockSecret")
	defer unsetEnv("RAPID_BASE_URL")
	defer unsetEnv("RAPID_KEY")
	defer unsetEnv("RAPID_SECRET")

	client, err := NewRapidClient()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if client == nil {
		t.Fatalf("Expected client to be non-nil")
	}
	if client.BaseURL != "http://mockapi.com" {
		t.Errorf("Expected BaseURL to be 'http://mockapi.com', got %v", client.BaseURL)
	}
	if client.Key != "mockKey" {
		t.Errorf("Expected Key to be 'mockKey', got %v", client.Key)
	}
	if client.Secret != "mockSecret" {
		t.Errorf("Expected Secret to be 'mockSecret', got %v", client.Secret)
	}
}

// Test for GenerateToken function
func TestGenerateToken(t *testing.T) {
	client := &RapidClient{
		BaseURL:    "http://mockapi.com",
		Key:        "mockKey",
		Secret:     "mockSecret",
		HTTPClient: &http.Client{},
	}

	// Mock the HTTP response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(mockTokenResponse))
		if err != nil {
			panic(err)
		}
	}))
	defer server.Close()

	client.BaseURL = server.URL

	err := client.GenerateToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if client.Token == nil {
		t.Fatalf("Expected Token to be non-nil")
	}
	if client.Token.Value != "mockAccessToken" {
		t.Errorf("Expected Token.Value to be 'mockAccessToken', got %v", client.Token.Value)
	}
	if client.Token.TokenType != "Bearer" {
		t.Errorf("Expected Token.TokenType to be 'Bearer', got %v", client.Token.TokenType)
	}
	if client.Token.RefreshToken != "mockRefreshToken" {
		t.Errorf("Expected Token.RefreshToken to be 'mockRefreshToken', got %v", client.Token.RefreshToken)
	}
}

// Test for IsValid function
func TestIsValid(t *testing.T) {
	token := NewToken("mockAccessToken", 3600, "Bearer", "mockRefreshToken")
	if !token.IsValid() {
		t.Errorf("Expected token to be valid")
	}

	// Expire the token
	token.ExpireTime = time.Now().Add(-1 * time.Hour)
	if token.IsValid() {
		t.Errorf("Expected token to be invalid")
	}
}

// Test for RefreshToken function
func TestRefreshToken(t *testing.T) {
	client := &RapidClient{
		BaseURL:    "http://mockapi.com",
		Key:        "mockKey",
		Secret:     "mockSecret",
		HTTPClient: &http.Client{},
		Token: &Token{
			RefreshToken: "mockRefreshToken",
		},
	}

	// Mock the HTTP response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(mockTokenResponse))
		if err != nil {
			panic(err)
		}
	}))
	defer server.Close()

	client.BaseURL = server.URL

	err := client.RefreshToken()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if client.Token == nil {
		t.Fatalf("Expected Token to be non-nil")
	}
	if client.Token.Value != "mockAccessToken" {
		t.Errorf("Expected Token.Value to be 'mockAccessToken', got %v", client.Token.Value)
	}
	if client.Token.TokenType != "Bearer" {
		t.Errorf("Expected Token.TokenType to be 'Bearer', got %v", client.Token.TokenType)
	}
	if client.Token.RefreshToken != "mockRefreshToken" {
		t.Errorf("Expected Token.RefreshToken to be 'mockRefreshToken', got %v", client.Token.RefreshToken)
	}
}

// Test for Request function
func TestRequest(t *testing.T) {
	client := &RapidClient{
		BaseURL:    "http://mockapi.com",
		Key:        "mockKey",
		Secret:     "mockSecret",
		HTTPClient: &http.Client{},
		Token: &Token{
			Value:      "mockAccessToken",
			TokenType:  "Bearer",
			ExpireTime: time.Now().Add(1 * time.Hour),
		},
	}

	// Mock the HTTP response
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"message": "success"}`))
		if err != nil {
			panic(err)
		}
	}))
	defer server.Close()

	client.BaseURL = server.URL

	resp, err := client.Request(http.MethodGet, "/mock-endpoint", nil, nil)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if resp == nil {
		t.Fatalf("Expected response to be non-nil")
	}

	var responseMap map[string]string
	err = json.Unmarshal(resp, &responseMap)
	if err != nil {
		t.Fatalf("Expected no error unmarshalling response, got %v", err)
	}
	if responseMap["message"] != "success" {
		t.Errorf("Expected response message to be 'success', got %v", responseMap["message"])
	}
}
