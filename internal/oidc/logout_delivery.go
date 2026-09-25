package oidc

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

// RunLogoutWorker is tied to server lifetime; leases survive process restarts.
// Sequential delivery bounds concurrency to one per process without holding a
// storage transaction open during DNS, signing, or HTTP requests.
func (s *Service) RunLogoutWorker(ctx context.Context, report func(error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if e := s.ProcessLogoutDeliveries(ctx); e != nil && ctx.Err() == nil {
			report(e)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Service) ProcessLogoutDeliveries(ctx context.Context) error {
	return s.processLogoutDelivery(ctx, "", "")
}
func (s *Service) processLogoutDelivery(ctx context.Context, opID, clientID string) error {
	if !s.logoutDeliveryMu.TryLock() {
		return nil
	}
	defer s.logoutDeliveryMu.Unlock()
	needed := false
	e := s.Store.Read(ctx, func(tx identity.ReadTx) error {
		now := s.Now()
		needed = tx.LogoutMaintenanceDue(now)
		for _, d := range tx.ListLogoutDeliveries() {
			if (opID == "" || d.OPSessionID == opID) && (clientID == "" || d.ClientID == clientID) && d.Channel == "backchannel" && (d.Status == "pending" || d.Status == "delivering") && !now.Before(d.NextAttempt) && !now.Before(d.LeaseUntil) {
				needed = true
				break
			}
		}
		return nil
	})
	if e != nil || !needed {
		return e
	}
	lease, e := randomToken()
	if e != nil {
		return e
	}
	var job *identity.LogoutDelivery
	e = s.Store.Write(ctx, func(tx identity.Tx) error {
		now := s.Now()
		tx.PruneLogoutState(now)
		jobs := tx.ListLogoutDeliveries()
		sort.Slice(jobs, func(i, j int) bool { return jobs[i].NextAttempt.Before(jobs[j].NextAttempt) })
		for _, d := range jobs {
			if (opID != "" && d.OPSessionID != opID) || (clientID != "" && d.ClientID != clientID) {
				continue
			}
			if d.Channel != "backchannel" || (d.Status != "pending" && d.Status != "delivering") || now.Before(d.NextAttempt) || now.Before(d.LeaseUntil) {
				continue
			}
			if now.Sub(d.CreatedAt) >= 24*time.Hour {
				d.Status = "failed"
				d.ErrorCode = "retry_window_expired"
				d.UpdatedAt = now
				tx.SaveLogoutDelivery(d)
				continue
			}
			// A deleted client still has a trusted destination snapshot. A changed
			// destination must not cause an old notification to be retargeted.
			if c, err := tx.Client(d.ClientID); err == nil && metadataString(c, "backchannel_logout_uri") != d.Endpoint {
				d.Status = "failed"
				d.ErrorCode = "destination_changed"
				d.UpdatedAt = now
				tx.SaveLogoutDelivery(d)
				continue
			}
			d.Status = "delivering"
			d.LeaseUntil = now.Add(30 * time.Second)
			d.LeaseID = lease
			d.Attempts++
			d.UpdatedAt = now
			tx.SaveLogoutDelivery(d)
			copy := d
			job = &copy
			break
		}
		return nil
	})
	if e != nil || job == nil {
		return e
	}
	code, retryAfter, errCode := s.sendLogout(ctx, *job)
	return s.Store.Write(ctx, func(tx identity.Tx) error {
		for _, d := range tx.ListLogoutDeliveries() {
			if d.ID != job.ID || d.LeaseID != lease {
				continue
			}
			now := s.Now()
			d.LeaseUntil = time.Time{}
			d.LeaseID = ""
			d.HTTPStatus = code
			d.ErrorCode = errCode
			d.UpdatedAt = now
			d.History = append(d.History, identity.LogoutAttempt{At: now, HTTPStatus: code, ErrorCode: errCode})
			if len(d.History) > 50 {
				d.History = d.History[len(d.History)-50:]
			}
			switch {
			case code == 200:
				d.Status = "acknowledged"
			case errCode == "unsafe_destination" || (code >= 400 && code < 500 && code != 429):
				d.Status = "failed"
			default:
				d.Status = "pending"
				delay := time.Duration(1<<min(d.Attempts, 10)) * time.Second
				delay += time.Duration(lease[0]%100) * delay / 100
				if retryAfter > delay {
					delay = retryAfter
				}
				if delay > time.Hour {
					delay = time.Hour
				}
				d.NextAttempt = now.Add(delay)
			}
			tx.SaveLogoutDelivery(d)
			break
		}
		return nil
	})
}

func (s *Service) sendLogout(ctx context.Context, d identity.LogoutDelivery) (int, time.Duration, string) {
	u, e := url.Parse(d.Endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "https" && !(s.Config.RegistrationAllowHTTP && u.Scheme == "http")) {
		return 0, 0, "unsafe_destination"
	}
	jti, e := randomToken()
	if e != nil {
		return 0, 0, "signing_unavailable"
	}
	now := s.Now()
	claims := map[string]any{"iss": s.Config.Issuer, "aud": d.ClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(), "jti": jti, "sid": d.AppSessionID, "sub": d.Subject, "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}} // NOSONAR: this is the exact OIDC Back-Channel Logout event claim URI, not a transport URL.
	if d.Subject == "" {
		delete(claims, "sub")
	}
	token, e := s.Keys.signTypedAt(now, "logout+jwt", claims)
	if e != nil {
		return 0, 0, "signing_unavailable"
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, DialContext: s.logoutDial, ResponseHeaderTimeout: 4 * time.Second, TLSHandshakeTimeout: 3 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(url.Values{"logout_token": {token}}.Encode()))
	if e != nil {
		return 0, 0, "unsafe_destination"
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, e := client.Do(req)
	if e != nil {
		if errors.Is(e, errUnsafeLogoutAddress) {
			return 0, 0, "unsafe_destination"
		}
		return 0, 0, "delivery_unavailable"
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	retry := time.Duration(0)
	if seconds, e := strconv.Atoi(response.Header.Get("Retry-After")); e == nil && seconds > 0 {
		retry = time.Duration(min(seconds, 3600)) * time.Second
	} else if stamp, e := http.ParseTime(response.Header.Get("Retry-After")); e == nil {
		retry = stamp.Sub(now)
	}
	if response.StatusCode != 200 {
		return response.StatusCode, retry, "http_error"
	}
	return 200, 0, ""
}

var errUnsafeLogoutAddress = errors.New("logout destination is not permitted")

func (s *Service) logoutDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errUnsafeLogoutAddress
	}
	ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, errUnsafeLogoutAddress
	}
	for _, v := range ips {
		ip := v.IP
		allowed := ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
		// Development permits only loopback, not arbitrary internal or metadata IPs.
		if s.Config.RegistrationAllowHTTP && ip.IsLoopback() {
			allowed = true
		}
		for _, cidr := range s.Config.LogoutAllowedCIDRs {
			_, block, e := net.ParseCIDR(cidr)
			if e == nil && block.Contains(ip) {
				allowed = true
			}
		}
		// Explicit private-network exceptions never permit unspecified or multicast destinations.
		if ip.IsUnspecified() || ip.IsMulticast() {
			allowed = false
		}
		if !allowed {
			return nil, errUnsafeLogoutAddress
		}
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	// Dial the checked IP, never resolve the hostname a second time. TLS still
	// verifies the original hostname through Transport's TLS configuration.
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}
