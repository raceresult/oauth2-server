package oauth2

// ResponseType the type of authorization request
type ResponseType string

// define the type of authorization request
const (
	Code  ResponseType = "code"
	Token ResponseType = "token"
)

func (rt ResponseType) String() string {
	return string(rt)
}

// GrantType authorization model
type GrantType string

// define authorization model
const (
	AuthorizationCode   GrantType = "authorization_code"
	PasswordCredentials GrantType = "password"
	ClientCredentials   GrantType = "client_credentials"
	Refreshing          GrantType = "refresh_token"
	PasswordHash        GrantType = "hash"
	PasswordPlain       GrantType = "password_plain"
	Implicit            GrantType = "__implicit"
)

func (gt GrantType) String() string {
	if gt == AuthorizationCode ||
		gt == PasswordCredentials ||
		gt == ClientCredentials ||
		gt == Refreshing ||
		gt == PasswordHash ||
		gt == PasswordPlain {
		return string(gt)
	}
	return ""
}
