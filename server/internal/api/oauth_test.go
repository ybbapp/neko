package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/m1k1o/neko/server/internal/config"
	"github.com/m1k1o/neko/server/internal/member"
	"github.com/m1k1o/neko/server/internal/session"
	"github.com/m1k1o/neko/server/pkg/types"
)

func TestOAuthLoginSynchronizesProfile(t *testing.T) {
	var tokenRequest url.Values
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			tokenRequest = r.Form
			_ = json.NewEncoder(w).Encode(map[string]string{"access_token": "provider-token"})
		case "/userinfo":
			if got := r.Header.Get("Authorization"); got != "Bearer provider-token" {
				http.Error(w, "missing provider authorization", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"sub":     "user-123",
				"name":    "Ada Lovelace",
				"picture": "https://example.test/ada.png",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	memberConfig := &config.Member{
		OAuth: config.OAuth{
			Enabled:          true,
			ClientID:         "client-id",
			ClientSecret:     "client-secret",
			AuthorizationURL: provider.URL + "/authorize",
			TokenURL:         provider.URL + "/token",
			UserInfoURL:      provider.URL + "/userinfo",
			RedirectURL:      "https://neko.example.test/api/oauth/callback",
			Scopes:           []string{"openid", "profile"},
			SubjectField:     "sub",
			UsernameField:    "name",
			AvatarField:      "picture",
			SuccessRedirect:  "/room",
			UserProfile: types.MemberProfile{
				CanLogin: true,
			},
		},
	}
	sessionManager := session.New(&config.Session{
		Cookie: config.SessionCookie{Enabled: true, Name: "NEKO_SESSION", Expiration: time.Hour},
	})
	members := member.New(sessionManager, memberConfig)
	api := New(sessionManager, members, nil, nil, memberConfig, &config.Server{PathPrefix: "/"})

	loginRecorder := httptest.NewRecorder()
	api.OAuthLogin(loginRecorder, httptest.NewRequest(http.MethodGet, "/api/oauth/login", nil))
	if loginRecorder.Code != http.StatusFound {
		t.Fatalf("login status = %d", loginRecorder.Code)
	}
	authorizeURL, err := url.Parse(loginRecorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizeURL.Query().Get("state")
	if state == "" || authorizeURL.Query().Get("code_challenge") == "" {
		t.Fatalf("OAuth redirect is missing state or PKCE challenge: %s", authorizeURL.String())
	}

	callbackRecorder := httptest.NewRecorder()
	callbackURL := "/api/oauth/callback?state=" + url.QueryEscape(state) + "&code=authorization-code"
	api.OAuthCallback(callbackRecorder, httptest.NewRequest(http.MethodGet, callbackURL, nil))
	if callbackRecorder.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d", callbackRecorder.Code)
	}
	if got := callbackRecorder.Header().Get("Location"); got != "/room" {
		t.Fatalf("redirect = %q", got)
	}
	if tokenRequest.Get("code_verifier") == "" {
		t.Fatal("token request is missing PKCE verifier")
	}
	if len(callbackRecorder.Result().Cookies()) != 1 {
		t.Fatal("OAuth callback did not set a session cookie")
	}

	userSession, ok := sessionManager.Get("oauth:user-123")
	if !ok {
		t.Fatal("OAuth session was not created")
	}
	profile := userSession.Profile()
	if profile.Name != "Ada Lovelace" || profile.Avatar != "https://example.test/ada.png" {
		t.Fatalf("profile = %#v", profile)
	}
}
