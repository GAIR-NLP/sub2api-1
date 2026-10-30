package service

import (
	"context"
	"fmt"

	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"
)

// Admin API-key management: single-read, status change, and delete.
//
// The user-facing APIKeyService paths are ownership-scoped (a user manages
// only their own keys). Deployments where sub2api runs as a pure middle
// layer (end users never touch it directly) need real admin-side key
// management; previously the admin API only accepted group_id updates and
// silently ignored every other field.

// AdminGetAPIKey returns a single API key by ID, for admin read-back
// verification after writes.
func (s *adminServiceImpl) AdminGetAPIKey(ctx context.Context, keyID int64) (*APIKey, error) {
	return s.apiKeyRepo.GetByID(ctx, keyID)
}

// AdminUpdateAPIKeyStatus sets a key's status to active/disabled as an admin.
// Idempotent: a key already in the requested state is returned unchanged.
func (s *adminServiceImpl) AdminUpdateAPIKeyStatus(ctx context.Context, keyID int64, status string) (*APIKey, error) {
	if status != StatusActive && status != StatusDisabled {
		return nil, infraerrors.BadRequest("INVALID_STATUS", "status must be active or disabled")
	}
	apiKey, err := s.apiKeyRepo.GetByID(ctx, keyID)
	if err != nil {
		return nil, err
	}
	if apiKey.Status == status {
		return apiKey, nil
	}
	apiKey.Status = status
	if err := s.apiKeyRepo.Update(ctx, apiKey, APIKeyUpdateFields{Status: true}); err != nil {
		return nil, fmt.Errorf("update api key status: %w", err)
	}
	// Status must take effect immediately at the auth layer.
	if s.authCacheInvalidator != nil {
		s.authCacheInvalidator.InvalidateAuthCacheByKey(ctx, apiKey.Key)
	}
	return apiKey, nil
}

// AdminDeleteAPIKey tombstone-deletes a key as an admin (soft delete + audit,
// credential material not retained). Mirrors the user-side Delete flow minus
// the ownership check — the admin token is the authorization boundary.
func (s *adminServiceImpl) AdminDeleteAPIKey(ctx context.Context, keyID int64) error {
	key, _, err := s.apiKeyRepo.GetKeyAndOwnerID(ctx, keyID)
	if err != nil {
		return fmt.Errorf("get api key: %w", err)
	}
	if err := s.apiKeyRepo.DeleteWithAudit(ctx, keyID); err != nil {
		return fmt.Errorf("delete api key: %w", err)
	}
	if s.authCacheInvalidator != nil {
		s.authCacheInvalidator.InvalidateAuthCacheByKey(ctx, key)
	}
	return nil
}
