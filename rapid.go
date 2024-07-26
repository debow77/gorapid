// Package rapid provides a client for interacting with the RAPID API.
//
// It handles authentication, token management, and provides methods for
// making HTTP requests to the API endpoints. The client uses environment
// variables for configuration to keep sensitive information out of the code.
package gorapid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type JSONBody interface {
	RapidJson() ([]byte, error)
}

type Response struct {
	Body    []byte
	Status  int
	Headers http.Header
	Error   error
}

// Token represents a RAPID API authentication token.
type Token struct {
	Value        string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpireTime   time.Time
}

// NewToken creates a new Token instance.
func NewToken(value string, expiresIn int, tokenType string, refreshToken string) *Token {
	return &Token{
		Value:        value,
		ExpiresIn:    expiresIn,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		ExpireTime:   time.Now().Add(time.Duration(expiresIn) * time.Second),
	}
}

// GetAuthorizationHeader returns the Authorization header value for the token.
func (t *Token) GetAuthorizationHeader() string {
	return fmt.Sprintf("%s %s", t.TokenType, t.Value)
}

// IsValid checks if the token is still valid based on its expiration time.
func (t *Token) IsValid() bool {
	return time.Now().Before(t.ExpireTime)
}

// RapidClient represents a client for interacting with the RAPID API.
type RapidClient struct {
	BaseURL        string
	Key            string
	Secret         string
	UserWebToken   string
	HTTPClient     *http.Client
	Token          *Token
	XAuthorization string
}

// NewRapidClient creates a new RapidClient instance using environment variables.
//
// The following environment variables are used:
//   - RAPID_BASE_URL: The base URL for the RAPID API (required).
//   - RAPID_KEY: The API key for authentication (required).
//   - RAPID_SECRET: The API secret for authentication (required).
//   - RAPID_USER_WEB_TOKEN: The user web token for authentication (optional).
//
// Returns:
//   - A new RapidClient instance and nil error on success.
//   - nil and an error if the required environment variables are not set.
func NewRapidClient() (*RapidClient, error) {
	baseURL := os.Getenv("RAPID_BASE_URL")
	key := os.Getenv("RAPID_KEY")
	secret := os.Getenv("RAPID_SECRET")
	userWebToken := os.Getenv("RAPID_USER_WEB_TOKEN")

	if baseURL == "" || key == "" || secret == "" {
		return nil, fmt.Errorf("RAPID_BASE_URL, RAPID_KEY, and RAPID_SECRET environment variables must be set")
	}

	return &RapidClient{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Key:          key,
		Secret:       secret,
		UserWebToken: userWebToken,
		HTTPClient:   &http.Client{Timeout: 600 * time.Second},
	}, nil
}

// GenerateToken generates a new RAPID Bearer token.
func (c *RapidClient) GenerateToken() error {
	params := c.generateParameters()
	tokenURL := c.BaseURL + "/token"

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Key+":"+c.Secret)))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("error decoding response: %w", err)
	}

	token.ExpireTime = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	c.Token = &token

	return nil
}

// RefreshToken refreshes an expired RAPID Bearer token.
func (c *RapidClient) RefreshToken() error {
	if c.Token == nil || c.Token.RefreshToken == "" {
		return c.GenerateToken()
	}

	params := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.Token.RefreshToken},
	}

	tokenURL := c.BaseURL + "/token"

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Key+":"+c.Secret)))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("error decoding response: %w", err)
	}

	token.ExpireTime = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	c.Token = &token

	return nil
}

// generateParameters generates the parameters for token requests.
func (c *RapidClient) generateParameters() url.Values {
	if c.UserWebToken != "" {
		return url.Values{
			"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
			"assertion":  {c.UserWebToken},
		}
	}
	return url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"am_application_scope,default"},
	}
}

// Request performs a generic RAPID request against the base API URL.
// The method automatically handles token generation and refresh as needed.
// It accepts HTTP method, URL path, request body, and query parameters.
// It returns the response body as a byte slice or an error if the request fails.
// func (c *RapidClient) Request(method, urlPath string, body interface{}, params url.Values) ([]byte, error) {
func (c *RapidClient) Request(method, urlPath string, body interface{}, params url.Values) (*Response, error) {
	if c.Token == nil || !c.Token.IsValid() {
		if err := c.GenerateToken(); err != nil {
			return nil, fmt.Errorf("error generating token: %w", err)
		}
	}

	fullURL := c.BaseURL + "/" + strings.TrimLeft(urlPath, "/")
	if len(params) > 0 {
		fullURL += "?" + params.Encode()
	}

	var reqBody []byte
	var err error
	if body != nil {
		if jsonBody, ok := body.(JSONBody); ok {
			reqBody, err = jsonBody.RapidJson()
		} else {
			reqBody, err = json.Marshal(body)
		}
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
	}

	var req *http.Request
	if body != nil {
		req, err = http.NewRequest(method, fullURL, bytes.NewBuffer(reqBody))
	} else {
		req, err = http.NewRequest(method, fullURL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	// Required for JIRA API
	if c.XAuthorization != "" {
		req.Header.Set("X-Authorization", c.XAuthorization)
	}

	req.Header.Set("Authorization", c.Token.GetAuthorizationHeader())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// return respBody, nil
	return &Response{
		Body:    respBody,
		Status:  resp.StatusCode,
		Headers: resp.Header,
		Error:   err,
	}, nil
}

// Get performs an HTTP GET request to the specified API endpoint.
func (c *RapidClient) Get(urlPath string, params url.Values) (*Response, error) {
	return c.Request(http.MethodGet, urlPath, nil, params)
}

// Post performs an HTTP POST request to the specified API endpoint.
func (c *RapidClient) Post(urlPath string, body JSONBody) (*Response, error) {
	return c.Request(http.MethodPost, urlPath, body, nil)
}

// Put performs an HTTP PUT request to the specified API endpoint.
func (c *RapidClient) Put(urlPath string, body JSONBody) (*Response, error) {
	return c.Request(http.MethodPut, urlPath, body, nil)
}

// Delete performs an HTTP DELETE request to the specified API endpoint.
func (c *RapidClient) Delete(urlPath string) (*Response, error) {
	return c.Request(http.MethodDelete, urlPath, nil, nil)
}
