package soju

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/machinebox/graphql"
)

type srhtUserType string

const (
	srhtUserUnconfirmed      srhtUserType = "UNCONFIRMED"
	srhtUserActiveNonPaying  srhtUserType = "ACTIVE_NON_PAYING"
	srhtUserActiveFree       srhtUserType = "ACTIVE_FREE"
	srhtUserActivePaying     srhtUserType = "ACTIVE_PAYING"
	srhtUserActiveDelinquent srhtUserType = "ACTIVE_DELINQUENT"
	srhtUserAdmin            srhtUserType = "ADMIN"
	srhtUserSuspended        srhtUserType = "SUSPENDED"
)

type srhtAuthIRCConn struct {
	ircConn
	auth *SrhtAuth
}

type SrhtAuth struct {
	Username string
	UserType srhtUserType
}

func checkSrhtCookie(ctx context.Context, cookie *http.Cookie) (*SrhtAuth, error) {
	h := make(http.Header)
	h.Set("Cookie", cookie.String())
	return checkSrhtAuth(ctx, h)
}

func checkSrhtToken(ctx context.Context, token string) (*SrhtAuth, error) {
	h := make(http.Header)
	h.Set("Authorization", "Bearer "+token)
	return checkSrhtAuth(ctx, h)
}

func checkSrhtAuth(ctx context.Context, h http.Header) (*SrhtAuth, error) {
	endpoint := "https://meta.sr.ht"
	if v, ok := os.LookupEnv("SRHT_ENDPOINT"); ok {
		endpoint = v
	}

	client := graphql.NewClient(endpoint + "/query")

	req := graphql.NewRequest(`
		query {
			me {
				username
				userType
			}
		}
	`)

	for k, vs := range h {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}

	var respData struct {
		Me struct {
			Username string
			UserType srhtUserType
		}
	}
	if err := client.Run(ctx, req, &respData); err != nil {
		return nil, &authError{
			err:    fmt.Errorf("failed to check sr.ht OAuth2 access token: %w", err),
			reason: "Invalid sr.ht OAuth2 access token",
		}
	}

	return &SrhtAuth{
		Username: respData.Me.Username,
		UserType: respData.Me.UserType,
	}, nil
}

func getOrCreateSrhtUser(ctx context.Context, srv *Server, auth *SrhtAuth) (*user, error) {
	u := srv.getUser(auth.Username)
	if u != nil {
		return u, nil
	}

	if os.Getenv("SRHT_USE_ALLOWLIST") == "1" {
		return nil, &authError{
			err:    fmt.Errorf("user missing from allow-list"),
			reason: "chat.sr.ht is in closed beta",
		}
	}

	switch auth.UserType {
	case srhtUserUnconfirmed:
		return nil, &authError{
			err:    fmt.Errorf("sr.ht account unconfirmed"),
			reason: "Please confirm your sr.ht account",
		}
	case srhtUserSuspended:
		return nil, &authError{
			err:    fmt.Errorf("sr.ht account suspended"),
			reason: "Your sr.ht account is suspended",
		}
	case srhtUserActiveNonPaying, srhtUserActiveDelinquent:
		if os.Getenv("SRHT_ALLOW_NON_PAYING") != "1" {
			return nil, &authError{
				err:    fmt.Errorf("sr.ht account non-paying"),
				reason: "Access to chat.sr.ht requires a paid account. Please set up billing at https://meta.sr.ht/billing and try again. For more information, consult https://man.sr.ht/billing-faq.md",
			}
		}
	case srhtUserActiveFree, srhtUserActivePaying, srhtUserAdmin:
		// Allowed
	default:
		return nil, fmt.Errorf("unexpected sr.ht user type %q", auth.UserType)
	}

	record := User{Username: auth.Username}
	return srv.createUser(ctx, &record)
}
