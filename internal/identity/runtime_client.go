package identity

import (
	"context"
	"encoding/json"
)

// ProtocolClient is a narrow, typed projection of a registered client's
// metadata for use by the OpenID Connect protocol endpoints. Unlike the
// admin-facing ClientView, it never requires an admin browser session:
// /authorize and /token must be able to look up a client from an
// unauthenticated relying-party request.
type ProtocolClient struct {
	ID                       string
	Secret                   string
	RedirectURIs             []string
	ResponseTypes            []string
	GrantTypes               []string
	TokenEndpointAuthMethod  string
	SubjectType              string
	IDTokenSignedResponseAlg string
	RequireAuthTime          bool
	DefaultMaxAge            *int64
	UpdatedAt                int64 // Monotonic nanosecond policy revision
	Compatible               bool
	IncompatibilityReasons   []string
}

func projectRuntimeClient(c ClientRecord) ProtocolClient {
	m := c.Metadata
	compatible, reasons := auditMetadata(m)
	var maxAge *int64
	_ = json.Unmarshal(m["default_max_age"], &maxAge)
	var requireAuthTime bool
	_ = json.Unmarshal(m["require_auth_time"], &requireAuthTime)
	return ProtocolClient{
		ID:                       c.ID,
		Secret:                   c.Secret,
		RedirectURIs:             m.list("redirect_uris"),
		ResponseTypes:            m.list("response_types"),
		GrantTypes:               m.list("grant_types"),
		TokenEndpointAuthMethod:  m.text("token_endpoint_auth_method"),
		SubjectType:              m.text("subject_type"),
		IDTokenSignedResponseAlg: m.text("id_token_signed_response_alg"),
		RequireAuthTime:          requireAuthTime,
		DefaultMaxAge:            maxAge,
		UpdatedAt:                c.UpdatedAt.UnixNano(),
		Compatible:               compatible,
		IncompatibilityReasons:   reasons,
	}
}

// ProtocolClient looks up a client for protocol use (authorize/token/etc.).
// It deliberately takes no session hash: callers are unauthenticated
// relying parties, not admin browser sessions.
func (s *Service) ProtocolClient(ctx context.Context, id string) (ProtocolClient, error) {
	var result ProtocolClient
	err := s.store.Read(ctx, func(tx ReadTx) error {
		c, err := tx.Client(id)
		if err != nil {
			return err
		}
		result = projectRuntimeClient(c)
		return nil
	})
	return result, err
}

// RuntimeClient projects a client snapshot inside an existing transaction.
func RuntimeClient(c ClientRecord) ProtocolClient { return projectRuntimeClient(c) }
