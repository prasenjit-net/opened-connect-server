package main

// Config is fixed at process startup from CLI flags: the issuer via
// -issuer, everything else derived from -addr/-public-url. There is
// nothing here for the user to edit at runtime - every flow instead takes
// its own client_id/secret/scopes/etc. from a form at the point it's
// started, since a real RP developer usually tests several different
// clients (public vs confidential, different grants) against the same OP
// in one sitting.
type Config struct {
	Issuer string

	RedirectURI           string
	PostLogoutRedirectURI string
	FrontChannelLogoutURI string
	BackChannelLogoutURI  string
}

func defaultConfig(selfBase, issuer string) *Config {
	return &Config{
		Issuer:                issuer,
		RedirectURI:           selfBase + "/callback",
		PostLogoutRedirectURI: selfBase + "/logged-out",
		FrontChannelLogoutURI: selfBase + "/frontchannel-logout",
		BackChannelLogoutURI:  selfBase + "/backchannel-logout",
	}
}
