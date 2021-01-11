package oauth2

import (
	"net/http"
	"time"
)

// TokenGenerateRequest provide to generate the token request parameters
type TokenGenerateRequest struct {
	ClientID       string
	ClientSecret   string
	UserID         string
	RedirectURI    string
	Scope          string
	Code           string
	Refresh        string
	AccessTokenExp time.Duration
	Request        *http.Request
}

// Manager authorization management interface
type Manager interface {
	// GetClient gets the client information
	GetClient(clientID string) (cli ClientInfo, err error)

	// GenerateAuthToken generates the authorization token(code)
	GenerateAuthToken(rt ResponseType, tgr *TokenGenerateRequest) (authToken TokenInfo, err error)

	// GenerateAccessToken generates the access token
	GenerateAccessToken(rt GrantType, tgr *TokenGenerateRequest) (accessToken TokenInfo, err error)

	// RefreshAccessToken refreshes an access token
	RefreshAccessToken(tgr *TokenGenerateRequest) (accessToken TokenInfo, err error)

	// RemoveAccessToken uses the access token to delete the token information
	RemoveAccessToken(access string) (err error)

	// RemoveRefreshToken uses the refresh token to delete the token information
	RemoveRefreshToken(refresh string) (err error)

	// LoadAccessToken returns corresponding token information for the access token
	LoadAccessToken(access string) (ti TokenInfo, err error)

	// LoadRefreshToken return corresponding token information for the refresh token
	LoadRefreshToken(refresh string) (ti TokenInfo, err error)
}
