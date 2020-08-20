package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/sessions"
)

const (
	AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenEndpoint         = "https://oauth2.googleapis.com/token"
)

var (
	ClientID     = os.Getenv("OAUTH2_CLIENT_ID")
	ClientSecret = os.Getenv("OAUTH2_CLIENT_SECRET")
	RedirectURL  = os.Getenv("OAUTH2_REDIRECT_URL")
)

type TokenEntity struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	Expiry       time.Time
}

func GetTokenFromSession(s *sessions.Session) (*TokenEntity, error) {
	accessToken, ok := s.Values["oauth2_access_token"]
	if !ok {
		return nil, errors.New("OAuth2 session is not saved in the user-agent")
	}

	expiresIn, ok := s.Values["oauth2_expires_in"]
	if !ok {
		return nil, errors.New("OAuth2 session is not saved in the user-agent")
	}

	refreshToken, ok := s.Values["oauth2_refresh_token"]
	if !ok {
		return nil, errors.New("OAuth2 session is not saved in the user-agent")
	}

	scope, ok := s.Values["oauth2_scope"]
	if !ok {
		return nil, errors.New("OAuth2 session is not saved in the user-agent")
	}

	tokenType, ok := s.Values["oauth2_token_type"]
	if !ok {
		return nil, errors.New("OAuth2 session is not saved in the user-agent")
	}

	expiresInInt, _ := strconv.Atoi(expiresIn.(string))
	token := TokenEntity{
		AccessToken:  accessToken.(string),
		ExpiresIn:    expiresInInt,
		RefreshToken: refreshToken.(string),
		Scope:        scope.(string),
		TokenType:    tokenType.(string),
		Expiry:       time.Now().Add(time.Duration(expiresInInt) * time.Second),
	}
	return &token, nil
}

func CreateAuthorizationRequestURL(scopes []string) (*url.URL, error) {
	u, err := url.Parse(AuthorizationEndpoint)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Add("client_id", ClientID)
	q.Add("redirect_uri", RedirectURL)
	q.Add("response_type", "code")
	q.Add("scope", strings.Join(scopes, " "))

	u.RawQuery = q.Encode()
	return u, nil
}

func ExchangeToken(ctx context.Context, code string) (*TokenEntity, error) {
	v := url.Values{
		"client_id":     {ClientID},
		"client_secret": {ClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {RedirectURL},
	}

	req, err := http.NewRequest("POST", TokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(ClientID), url.QueryEscape(ClientSecret))

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if code := resp.StatusCode; !(code >= 200 && code < 300) {
		return nil, fmt.Errorf("oauth2: token request failed: status_code=%v body=%v", code, string(body))
	}

	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	if contentType != "application/json" {
		return nil, fmt.Errorf("oauth2: invalid Content-Type in response: %v", contentType)
	}

	token := TokenEntity{}
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	if token.ExpiresIn != 0 {
		token.Expiry = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	}

	return &token, nil
}
