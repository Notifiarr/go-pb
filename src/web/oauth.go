package web

import (
	"github.com/go-pkgz/auth"
	"github.com/go-pkgz/auth/avatar"
	"github.com/go-pkgz/auth/provider"
	"github.com/go-pkgz/auth/token"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

func (handler *Server) authMiddleware(storageDir string) *auth.Service {
	// Auth middleware
	authSvc := auth.NewService(auth.Opts{
		SecretReader: token.SecretFunc(func(id string) (string, error) { // secret key for JWT
			return handler.options.AuthSecret, nil
		}),
		TokenDuration:  handler.options.AuthTokenDuration,
		CookieDuration: handler.options.AuthCookieDuration,
		Issuer:         handler.options.AuthIssuer,
		URL:            handler.options.AuthURL,
		DisableXSRF:    true,
		AvatarStore:    avatar.NewLocalFS(storageDir),
		Logger:         handler.log, // optional logger for auth library
	})

	authSvc.AddCustomProvider("discord_custom", auth.Client{
		Cid:     handler.options.DiscordCID,
		Csecret: handler.options.DiscordCSEC,
	}, provider.CustomHandlerOpt{
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://discord.com/api/oauth2/authorize",
			TokenURL: "https://discord.com/api/v8/oauth2/token",
		},
		InfoURL: "https://discord.com/api/v8/users/@me",
		Scopes:  []string{"identify", "email"},
		MapUserFn: func(data provider.UserData, _ []byte) token.User {
			return token.User{
				ID:      data.Value("email"),
				Name:    data.Value("username"),
				Picture: "https://cdn.discordapp.com/avatars/" + data.Value("id") + "/" + data.Value("avatar") + ".png",
			}
		},
	})

	authSvc.AddCustomProvider("google_custom", auth.Client{
		Cid:     handler.options.GoogleCID,
		Csecret: handler.options.GoogleCSEC,
	}, provider.CustomHandlerOpt{
		Endpoint: google.Endpoint,
		InfoURL:  "https://www.googleapis.com/oauth2/v3/userinfo",
		Scopes:   []string{"https://www.googleapis.com/auth/userinfo.profile"},
		MapUserFn: func(data provider.UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      data.Value("sub"),
				Name:    data.Value("name"),
				Picture: data.Value("picture"),
			}
			if userInfo.Name == "" {
				userInfo.Name = "noname_" + userInfo.ID[8:12]
			}

			return userInfo
		},
	})

	authSvc.AddCustomProvider("github_custom", auth.Client{
		Cid:     handler.options.GitHubCID,
		Csecret: handler.options.GitHubCSEC,
	}, provider.CustomHandlerOpt{
		Endpoint: github.Endpoint,
		InfoURL:  "https://api.github.com/user",
		MapUserFn: func(data provider.UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      data.Value("email"),
				Name:    data.Value("name"),
				Picture: data.Value("avatar_url"),
			}
			// github may have no user name, use login in this case
			if userInfo.Name == "" {
				userInfo.Name = data.Value("login")
			}

			if userInfo.Name == "" {
				userInfo.Name = "noname_" + userInfo.ID[8:12]
			}

			return userInfo
		},
	})

	authSvc.AddCustomProvider("twitter_custom", auth.Client{
		Cid:     handler.options.TwitterCID,
		Csecret: handler.options.TwitterCSEC,
	}, provider.CustomHandlerOpt{
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://api.twitter.com/oauth/request_token",
			AuthURL:  "https://api.twitter.com/oauth/authorize",
		},
		InfoURL: "https://api.twitter.com/1.1/account/verify_credentials.json",
		MapUserFn: func(data provider.UserData, _ []byte) token.User {
			userInfo := token.User{
				ID:      data.Value("email"),
				Name:    data.Value("screen_name"),
				Picture: data.Value("profile_image_url_https"),
			}
			if userInfo.Name == "" {
				userInfo.Name = data.Value("name")
			}

			return userInfo
		},
	})

	authSvc.AddProvider("dev", "", "") // dev auth, runs dev oauth2 server on :8084

	return authSvc
}
