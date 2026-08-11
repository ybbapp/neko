package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/m1k1o/neko/server/internal/config"
	"github.com/m1k1o/neko/server/pkg/types"
	"github.com/m1k1o/neko/server/pkg/utils"
)

const oauthStateLifetime = 10 * time.Minute

type oauthState struct {
	verifier string
	expires  time.Time
}

type oauthHandler struct {
	config     config.OAuth
	client     *http.Client
	pathPrefix string
	mu         sync.Mutex
	states     map[string]oauthState
}

func newOAuthHandler(config config.OAuth, pathPrefix string) *oauthHandler {
	if pathPrefix == "" {
		pathPrefix = "/"
	}
	return &oauthHandler{
		config:     config,
		client:     &http.Client{Timeout: 15 * time.Second},
		pathPrefix: pathPrefix,
		states:     make(map[string]oauthState),
	}
}

func (handler *oauthHandler) configured() bool {
	config := handler.config
	return config.Enabled && config.ClientID != "" && config.ClientSecret != "" &&
		config.AuthorizationURL != "" && config.TokenURL != "" && config.UserInfoURL != "" &&
		config.RedirectURL != ""
}

func (api *ApiManagerCtx) OAuthLogin(w http.ResponseWriter, r *http.Request) error {
	if !api.oauth.config.Enabled {
		return utils.HttpNotFound()
	}
	if !api.oauth.configured() {
		return utils.HttpError(http.StatusServiceUnavailable, "OAuth is not fully configured")
	}
	if !api.sessions.CookieEnabled() {
		return utils.HttpError(http.StatusServiceUnavailable, "OAuth requires session cookies to be enabled")
	}

	state, err := newOAuthToken(32)
	if err != nil {
		return utils.HttpInternalServerError().WithInternalErr(err)
	}
	verifier, err := newOAuthToken(64)
	if err != nil {
		return utils.HttpInternalServerError().WithInternalErr(err)
	}

	api.oauth.storeState(state, verifier)

	authorizationURL, err := url.Parse(api.oauth.config.AuthorizationURL)
	if err != nil {
		return utils.HttpInternalServerError("invalid OAuth authorization URL").WithInternalErr(err)
	}
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", api.oauth.config.ClientID)
	query.Set("redirect_uri", api.oauth.config.RedirectURL)
	query.Set("scope", strings.Join(api.oauth.config.Scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", oauthChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	http.Redirect(w, r, authorizationURL.String(), http.StatusFound)
	return nil
}

func (api *ApiManagerCtx) OAuthCallback(w http.ResponseWriter, r *http.Request) error {
	if !api.oauth.config.Enabled {
		return utils.HttpNotFound()
	}
	if !api.oauth.configured() {
		return utils.HttpError(http.StatusServiceUnavailable, "OAuth is not fully configured")
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		return utils.HttpUnauthorized("OAuth authorization was declined").WithInternalMsg(providerError)
	}

	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		return utils.HttpBadRequest("OAuth callback is missing state or code")
	}
	verifier, ok := api.oauth.popState(state)
	if !ok {
		return utils.HttpBadRequest("OAuth state is invalid or expired")
	}

	accessToken, err := api.oauth.exchangeCode(r, code, verifier)
	if err != nil {
		return utils.HttpUnauthorized("OAuth token exchange failed").WithInternalErr(err)
	}
	claims, err := api.oauth.userInfo(r, accessToken)
	if err != nil {
		return utils.HttpUnauthorized("OAuth user-info request failed").WithInternalErr(err)
	}

	subject := oauthClaim(claims, api.oauth.config.SubjectField)
	if subject == "" {
		return utils.HttpUnauthorized("OAuth user-info response is missing the subject field")
	}
	name := oauthClaim(claims, api.oauth.config.UsernameField)
	if name == "" {
		name = subject
	}
	avatar := oauthClaim(claims, api.oauth.config.AvatarField)

	_, token, err := api.members.LoginOAuth(subject, name, avatar)
	if err != nil {
		if errors.Is(err, types.ErrSessionAlreadyConnected) {
			return utils.HttpUnprocessableEntity("session already connected")
		}
		if errors.Is(err, types.ErrSessionLoginsLocked) {
			return utils.HttpForbidden("logins are locked").WithInternalErr(err)
		}
		return utils.HttpInternalServerError().WithInternalErr(err)
	}

	api.sessions.CookieSetToken(w, token)
	http.Redirect(w, r, api.oauth.successRedirect(), http.StatusSeeOther)
	return nil
}

func (handler *oauthHandler) storeState(state, verifier string) {
	handler.mu.Lock()
	defer handler.mu.Unlock()

	now := time.Now()
	for key, value := range handler.states {
		if now.After(value.expires) {
			delete(handler.states, key)
		}
	}
	handler.states[state] = oauthState{verifier: verifier, expires: now.Add(oauthStateLifetime)}
}

func (handler *oauthHandler) popState(state string) (string, bool) {
	handler.mu.Lock()
	defer handler.mu.Unlock()

	value, ok := handler.states[state]
	delete(handler.states, state)
	return value.verifier, ok && time.Now().Before(value.expires)
}

func (handler *oauthHandler) exchangeCode(r *http.Request, code, verifier string) (string, error) {
	values := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {handler.config.RedirectURL},
		"client_id":     {handler.config.ClientID},
		"client_secret": {handler.config.ClientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, handler.config.TokenURL, strings.NewReader(values.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	response, err := handler.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("token endpoint returned %s", response.Status)
	}

	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload); err != nil {
		return "", err
	}
	if payload.AccessToken == "" {
		return "", errors.New("token response has no access_token")
	}
	return payload.AccessToken, nil
}

func (handler *oauthHandler) userInfo(r *http.Request, accessToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, handler.config.UserInfoURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)

	response, err := handler.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("user-info endpoint returned %s", response.Status)
	}

	claims := map[string]any{}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func (handler *oauthHandler) successRedirect() string {
	redirect := handler.config.SuccessRedirect
	if strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") {
		return path.Join(handler.pathPrefix, redirect)
	}
	return handler.pathPrefix
}

func newOAuthToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func oauthChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func oauthClaim(claims map[string]any, field string) string {
	value, ok := claims[field]
	if !ok {
		return ""
	}
	return fmt.Sprint(value)
}
