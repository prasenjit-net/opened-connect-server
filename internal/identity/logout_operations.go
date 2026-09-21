package identity

import (
	"context"
	"slices"
	"time"
)

// Operations group multiple session terminations without copying credentials or
// notification payloads. Delivery state remains in the durable outbox.
type LogoutOperation struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"createdAt"`
	Targets   []string  `json:"targets"`
}

func (s *fileState) LogoutOperation(id string) (LogoutOperation, error) {
	v, ok := s.LogoutOperations[id]
	if !ok {
		return v, ErrNotFound
	}
	v.Targets = append([]string{}, v.Targets...)
	return v, nil
}
func (s *fileState) SaveLogoutOperation(v LogoutOperation) {
	if s.LogoutOperations == nil {
		s.LogoutOperations = map[string]LogoutOperation{}
	}
	// Operational history is bounded independently of required delivery intents.
	if len(s.LogoutOperations) >= 10000 {
		oldest := ""
		var stamp time.Time
		for id, op := range s.LogoutOperations {
			if oldest == "" || op.CreatedAt.Before(stamp) {
				oldest = id
				stamp = op.CreatedAt
			}
		}
		delete(s.LogoutOperations, oldest)
	}
	v.Targets = append([]string{}, v.Targets...)
	s.LogoutOperations[v.ID] = v
}

type LogoutDeliveryDetail struct {
	History      []LogoutAttempt `json:"history,omitempty"`
	ID           string          `json:"id"`
	AppSessionID string          `json:"appSessionId,omitempty"`
	ClientID     string          `json:"clientId,omitempty"`
	Channel      string          `json:"channel"`
	Status       string          `json:"status"`
	Attempts     int             `json:"attempts"`
	HTTPStatus   int             `json:"httpStatus,omitempty"`
	ErrorCode    string          `json:"errorCode,omitempty"`
	NextAttempt  time.Time       `json:"nextAttempt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
}
type LogoutOperationDetail struct {
	Operation    LogoutOperation        `json:"operation"`
	LocalOutcome string                 `json:"localOutcome"`
	Deliveries   []LogoutDeliveryDetail `json:"deliveries"`
}

func (s *Service) LogoutOperationDetail(ctx context.Context, hash, id string) (LogoutOperationDetail, error) {
	out := LogoutOperationDetail{LocalOutcome: "ended", Deliveries: []LogoutDeliveryDetail{}}
	e := s.store.Read(ctx, func(tx ReadTx) error {
		if _, e := s.principal(tx, hash, true); e != nil {
			return e
		}
		op, e := tx.LogoutOperation(id)
		if e != nil {
			return e
		}
		out.Operation = op
		for _, d := range tx.ListLogoutDeliveries() {
			if !slices.Contains(op.Targets, d.OPSessionID) && !slices.Contains(op.Targets, d.AppSessionID) {
				continue
			}
			out.Deliveries = append(out.Deliveries, LogoutDeliveryDetail{History: d.History, ID: d.ID, AppSessionID: d.AppSessionID, ClientID: d.ClientID, Channel: d.Channel, Status: d.Status, Attempts: d.Attempts, HTTPStatus: d.HTTPStatus, ErrorCode: d.ErrorCode, NextAttempt: d.NextAttempt, UpdatedAt: d.UpdatedAt})
		}
		return nil
	})
	return out, e
}
