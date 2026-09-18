package identity

func (s *fileState) OAuthPolicy(id string) OAuthPolicy { return clonePolicy(s.OAuthPolicies[id]) }
func (s *fileState) SaveOAuthPolicy(id string, p OAuthPolicy) {
	if s.OAuthPolicies == nil {
		s.OAuthPolicies = map[string]OAuthPolicy{}
	}
	s.OAuthPolicies[id] = clonePolicy(p)
	s.invalidateClientGrants(id)
}
func (s *fileState) OAuthAccess(id string) OAuthAccess { return cloneAccess(s.UserOAuthAccess[id]) }
func (s *fileState) SaveOAuthAccess(id string, a OAuthAccess) {
	if s.UserOAuthAccess == nil {
		s.UserOAuthAccess = map[string]OAuthAccess{}
	}
	s.UserOAuthAccess[id] = cloneAccess(a)
	s.RevokeAccessTokensForUser(id)
}
func (s *fileState) RefreshFamily(id string) (RefreshFamily, error) {
	f, ok := s.RefreshFamilies[id]
	if !ok {
		return f, ErrNotFound
	}
	return cloneFamily(f), nil
}
func (s *fileState) RefreshToken(hash string) (RefreshToken, error) {
	t, ok := s.RefreshTokens[hash]
	if !ok {
		return t, ErrNotFound
	}
	return cloneRefresh(t), nil
}
func (s *fileState) ListRefreshFamilies() []RefreshFamily {
	out := []RefreshFamily{}
	for _, f := range s.RefreshFamilies {
		out = append(out, cloneFamily(f))
	}
	return out
}
func (s *fileState) ListRefreshTokens() []RefreshToken {
	out := []RefreshToken{}
	for _, r := range s.RefreshTokens {
		out = append(out, cloneRefresh(r))
	}
	return out
}
func (s *fileState) SaveRefreshFamily(f RefreshFamily) {
	if s.RefreshFamilies == nil {
		s.RefreshFamilies = map[string]RefreshFamily{}
	}
	s.RefreshFamilies[f.ID] = cloneFamily(f)
}
func (s *fileState) SaveRefreshToken(t RefreshToken) {
	if s.RefreshTokens == nil {
		s.RefreshTokens = map[string]RefreshToken{}
	}
	s.RefreshTokens[t.Hash] = cloneRefresh(t)
}
func (s *fileState) RevokeRefreshFamily(id string) {
	f, ok := s.RefreshFamilies[id]
	if !ok {
		return
	}
	f.Revoked = true
	s.RefreshFamilies[id] = f
	for h, t := range s.AccessTokens {
		if t.FamilyID == id {
			t.Revoked = true
			s.AccessTokens[h] = t
		}
	}
}
