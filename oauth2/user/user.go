package user

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"

	"github.com/yuru-dev/SimpleAuthWeb01/oauth2"
)

type User struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"`
}

const GetProfileURL = "https://www.googleapis.com/oauth2/v2/userinfo"

func RequestUserProfile(t *oauth2.TokenEntity) (*User, error) {
	req, err := http.NewRequest("GET", GetProfileURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", t.TokenType, t.AccessToken))

	resp, err := http.DefaultClient.Do(req)
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

	user := User{}
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, err
	}

	return &user, nil
}
