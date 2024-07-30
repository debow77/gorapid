package gorapid

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	contentTypeJSON        = "application/json"
	contentTypeURLEncoded  = "application/x-www-form-urlencoded"
	authorizationHeader    = "Authorization"
	xAuthorizationHeader   = "X-Authorization"
	acceptHeader           = "Accept"
	defaultTimeout         = 600 * time.Second
	tokenEndpoint          = "/token"
	clientCredentialsGrant = "client_credentials"
	jwtBearerGrant         = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Custom errors
var (
	ErrInvalidConfig    = errors.New("invalid configuration: base URL, key, and secret must be provided")
	ErrTokenGeneration  = errors.New("failed to generate token")
	ErrUnexpectedStatus = errors.New("unexpected status code")
)

// Config holds the configuration for RapidClient
type Config struct {
	BaseURL      string
	Key          string
	Secret       string
	UserWebToken string
	Timeout      time.Duration
}

// JSONBody defines an interface for types that can be converted to JSON.
type JSONBody interface {
	RapidJson() ([]byte, error)
}

// Response represents the structure of an HTTP response.
type Response struct {
	Body         io.ReadCloser
	Status       int
	Headers      http.Header
	Error        error
	ResponseTime time.Duration
	RequestURL   string
}

type readOnlyBytes struct {
	*bytes.Reader
}

func (r *readOnlyBytes) Close() error {
	return nil
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
func NewToken(value string, expiresIn int, tokenType, refreshToken string) *Token {
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

// NewRapidClient creates a new RapidClient instance using environment variables
func NewRapidClient() (*RapidClient, error) {
	baseURL := os.Getenv("RAPID_BASE_URL")
	key := os.Getenv("RAPID_KEY")
	secret := os.Getenv("RAPID_SECRET")
	userWebToken := os.Getenv("RAPID_USER_WEB_TOKEN")

	if baseURL == "" || key == "" || secret == "" {
		return nil, ErrInvalidConfig
	}

	return &RapidClient{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Key:          key,
		Secret:       secret,
		UserWebToken: userWebToken,
		HTTPClient:   &http.Client{Timeout: defaultTimeout},
	}, nil
}

// GenerateToken generates a new RAPID Bearer token.
func (c *RapidClient) GenerateToken() error {
	return c.generateOrRefreshToken(false)
}

// RefreshToken refreshes an expired RAPID Bearer token.
func (c *RapidClient) RefreshToken() error {
	return c.generateOrRefreshToken(true)
}

func (c *RapidClient) generateOrRefreshToken(isRefresh bool) error {
	params := c.generateParameters(isRefresh)
	tokenURL := c.BaseURL + tokenEndpoint

	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	req.Header.Set("Content-Type", contentTypeURLEncoded)
	req.Header.Set(authorizationHeader, "Basic "+base64.StdEncoding.EncodeToString([]byte(c.Key+":"+c.Secret)))

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %d", ErrUnexpectedStatus, resp.StatusCode)
	}

	var token Token
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenGeneration, err)
	}

	token.ExpireTime = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	c.Token = &token

	return nil
}

// generateParameters generates the parameters for token requests.
func (c *RapidClient) generateParameters(isRefresh bool) url.Values {
	if isRefresh && c.Token != nil && c.Token.RefreshToken != "" {
		return url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {c.Token.RefreshToken},
		}
	}
	if c.UserWebToken != "" {
		return url.Values{
			"grant_type": {jwtBearerGrant},
			"assertion":  {c.UserWebToken},
		}
	}
	return url.Values{
		"grant_type": {clientCredentialsGrant},
		"scope":      {"am_application_scope,default"},
	}
}

// ensureValidToken checks if the current token is valid and generates a new one if necessary.
func (c *RapidClient) ensureValidToken() error {
	if c.Token != nil && c.Token.IsValid() {
		return nil
	}
	return c.GenerateToken()
}

// Request performs a generic RAPID request against the base API URL.
// It handles token generation and refresh as needed and returns the response.
func (c *RapidClient) Request(method, urlPath string, body interface{}, params url.Values) (*Response, error) {
	if err := c.ensureValidToken(); err != nil {
		return nil, fmt.Errorf("error ensuring valid token: %w", err)
	}

	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing base URL: %w", err)
	}
	// u.Path = path.Join(u.Path, urlPath)
	u.Path = filepath.Join(u.Path, urlPath)
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}

	var reqBody io.ReadCloser
	if body != nil {
		var buf []byte
		if jsonBody, ok := body.(JSONBody); ok {
			buf, err = jsonBody.RapidJson()
		} else {
			buf, err = json.Marshal(body)
		}
		if err != nil {
			return nil, fmt.Errorf("error marshaling request body: %w", err)
		}
		reqBody = &readOnlyBytes{bytes.NewReader(buf)}
	}

	req, err := http.NewRequest(method, u.String(), reqBody)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	req.Header.Set(acceptHeader, contentTypeJSON)
	if c.XAuthorization != "" {
		req.Header.Set(xAuthorizationHeader, c.XAuthorization)
	}
	req.Header.Set(authorizationHeader, c.Token.GetAuthorizationHeader())
	if body != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}

	start := time.Now()
	resp, err := c.HTTPClient.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %w", err)
	}

	return &Response{
		Body:         resp.Body,
		Status:       resp.StatusCode,
		Headers:      resp.Header,
		Error:        err,
		ResponseTime: duration,
		RequestURL:   u.String(),
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
