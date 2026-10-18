package service

import (
	"context"
	"errors"
	"fmt"
	"log"

	"nginx-proxy-guard/internal/model"
	"nginx-proxy-guard/internal/nginx"
	"nginx-proxy-guard/internal/repository"
	"nginx-proxy-guard/pkg/cache"
)

// ---- URI Block ----

func (s *SecurityService) GetURIBlock(ctx context.Context, proxyHostID string) (*model.URIBlock, error) {
	uriBlock, err := s.uriBlockRepo.GetByProxyHostID(ctx, proxyHostID)
	if err != nil {
		return nil, fmt.Errorf("failed to get URI block: %w", err)
	}
	if uriBlock == nil {
		uriBlock = &model.URIBlock{
			ProxyHostID:     proxyHostID,
			Enabled:         false,
			Rules:           []model.URIBlockRule{},
			ExceptionIPs:    []string{},
			AllowPrivateIPs: true,

			ExceptionHostnames: []string{},
		}
	}
	return uriBlock, nil
}

func (s *SecurityService) UpsertURIBlock(ctx context.Context, proxyHostID string, req *model.CreateURIBlockRequest, skipReload bool) (*model.URIBlock, error) {
	uriBlock, err := s.uriBlockRepo.Upsert(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to upsert URI block: %w", err)
	}

	// Update cache
	s.cacheURIBlock(ctx, proxyHostID, uriBlock)

	// Regenerate nginx config with debounced reload (skip if requested)
	if !skipReload {
		host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
		if host != nil && host.Enabled && s.proxyHostService != nil {
			if _, err := s.proxyHostService.UpdateWithoutReload(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
				return nil, fmt.Errorf("failed to regenerate nginx config for URI block: %w", err)
			}
			if s.nginxReloader != nil {
				s.nginxReloader.RequestReload(ctx)
			}
		}
	}

	return uriBlock, nil
}

func (s *SecurityService) DeleteURIBlock(ctx context.Context, proxyHostID string) error {
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)

	if err := s.uriBlockRepo.Delete(ctx, proxyHostID); err != nil {
		return fmt.Errorf("failed to delete URI block: %w", err)
	}

	// Clear cache
	if s.redisCache != nil {
		s.redisCache.DeleteURIBlock(ctx, proxyHostID)
	}

	// Regenerate nginx config with debounced reload
	if host != nil && host.Enabled && s.proxyHostService != nil {
		if _, err := s.proxyHostService.UpdateWithoutReload(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return fmt.Errorf("failed to regenerate nginx config for URI block removal: %w", err)
		}
		if s.nginxReloader != nil {
			s.nginxReloader.RequestReload(ctx)
		}
	}

	return nil
}

func (s *SecurityService) AddURIBlockRule(ctx context.Context, proxyHostID string, req *model.AddURIBlockRuleRequest) (*model.URIBlock, error) {
	uriBlock, err := s.uriBlockRepo.AddRule(ctx, proxyHostID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to add URI block rule: %w", err)
	}

	// Update cache
	s.cacheURIBlock(ctx, proxyHostID, uriBlock)

	// Regenerate nginx config with debounced reload
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
	if host != nil && host.Enabled && s.proxyHostService != nil {
		if _, err := s.proxyHostService.UpdateWithoutReload(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return nil, fmt.Errorf("failed to regenerate nginx config for URI block rule: %w", err)
		}
		if s.nginxReloader != nil {
			s.nginxReloader.RequestReload(ctx)
		}
	}

	return uriBlock, nil
}

func (s *SecurityService) RemoveURIBlockRule(ctx context.Context, proxyHostID string, ruleID string) error {
	if err := s.uriBlockRepo.RemoveRule(ctx, proxyHostID, ruleID); err != nil {
		return fmt.Errorf("failed to remove URI block rule: %w", err)
	}

	// Update cache (re-fetch to get current state)
	if uriBlock, err := s.uriBlockRepo.GetByProxyHostID(ctx, proxyHostID); err == nil && uriBlock != nil {
		s.cacheURIBlock(ctx, proxyHostID, uriBlock)
	} else if s.redisCache != nil {
		s.redisCache.DeleteURIBlock(ctx, proxyHostID)
	}

	// Regenerate nginx config with debounced reload
	host, _ := s.proxyHostRepo.GetByID(ctx, proxyHostID)
	if host != nil && host.Enabled && s.proxyHostService != nil {
		if _, err := s.proxyHostService.UpdateWithoutReload(ctx, proxyHostID, &model.UpdateProxyHostRequest{}); err != nil {
			return fmt.Errorf("failed to regenerate nginx config for URI block rule removal: %w", err)
		}
		if s.nginxReloader != nil {
			s.nginxReloader.RequestReload(ctx)
		}
	}

	return nil
}

// BulkAddURIBlockRuleResult holds the result of a bulk URI block rule addition.
type BulkAddURIBlockRuleResult struct {
	AddedCount int      `json:"added_count"`
	TotalHosts int      `json:"total_hosts"`
	Pattern    string   `json:"pattern"`
	MatchType  string   `json:"match_type"`
	Errors     []string `json:"errors,omitempty"`
}

func (s *SecurityService) BulkAddURIBlockRule(ctx context.Context, pattern string, matchType string, description string, hostIDs []string) (*BulkAddURIBlockRuleResult, error) {
	var targetHostIDs []string

	if len(hostIDs) > 0 {
		targetHostIDs = hostIDs
	} else {
		allHosts, err := s.proxyHostRepo.GetAllEnabled(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get enabled hosts: %w", err)
		}
		for _, host := range allHosts {
			targetHostIDs = append(targetHostIDs, host.ID)
		}
	}

	if len(targetHostIDs) == 0 {
		return nil, fmt.Errorf("no target hosts found")
	}

	result := &BulkAddURIBlockRuleResult{
		TotalHosts: len(targetHostIDs),
		Pattern:    pattern,
		MatchType:  matchType,
	}

	enabled := true
	for _, hostID := range targetHostIDs {
		ruleReq := &model.AddURIBlockRuleRequest{
			Pattern:     pattern,
			MatchType:   model.URIMatchType(matchType),
			Description: description,
			Enabled:     &enabled,
		}

		uriBlock, err := s.uriBlockRepo.AddRule(ctx, hostID, ruleReq)
		if err != nil {
			result.Errors = append(result.Errors, hostID+": "+err.Error())
			continue
		}

		// Update cache
		s.cacheURIBlock(ctx, hostID, uriBlock)

		// Regenerate nginx config (without reload - we'll reload once at the end)
		host, _ := s.proxyHostRepo.GetByID(ctx, hostID)
		if host != nil && host.Enabled && s.proxyHostService != nil {
			s.proxyHostService.UpdateWithoutReload(ctx, hostID, &model.UpdateProxyHostRequest{})
		}

		result.AddedCount++
	}

	// Request single debounced reload after all configs are generated
	if s.nginxReloader != nil {
		s.nginxReloader.RequestReload(ctx)
	}

	return result, nil
}

func (s *SecurityService) ListAllURIBlocks(ctx context.Context) ([]repository.URIBlockWithHost, error) {
	blocks, err := s.uriBlockRepo.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list all URI blocks: %w", err)
	}
	return blocks, nil
}

// ---- Global URI Block ----

func (s *SecurityService) GetGlobalURIBlock(ctx context.Context) (*model.GlobalURIBlock, error) {
	block, err := s.uriBlockRepo.GetGlobalURIBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get global URI block: %w", err)
	}
	if block == nil {
		return &model.GlobalURIBlock{
			Enabled:         false,
			Rules:           []model.URIBlockRule{},
			ExceptionIPs:    []string{},
			AllowPrivateIPs: true,

			ExceptionHostnames: []string{},
		}, nil
	}
	return block, nil
}

func (s *SecurityService) UpdateGlobalURIBlock(ctx context.Context, req *model.CreateGlobalURIBlockRequest) (*model.GlobalURIBlock, error) {
	block, err := s.uriBlockRepo.UpsertGlobalURIBlock(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to update global URI block: %w", err)
	}

	// Sync all proxy host configs to apply global rules (synchronous)
	if s.proxyHostService != nil {
		if err := s.proxyHostService.SyncAllConfigs(context.Background()); err != nil {
			log.Printf("[SecurityService] Failed to sync proxy host configs: %v", err)
			// The block is saved and its files are on disk: the handler
			// records it and answers 409. Other failures are only logged.
			if errors.Is(err, nginx.ErrReloadRejected) {
				return block, fmt.Errorf("apply the global URI block: %w", err)
			}
		}
	}

	return block, nil
}

func (s *SecurityService) AddGlobalURIBlockRule(ctx context.Context, req *model.AddURIBlockRuleRequest) (*model.GlobalURIBlock, error) {
	block, err := s.uriBlockRepo.AddGlobalRule(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to add global URI block rule: %w", err)
	}

	// Sync all proxy host configs in background
	go s.syncAllProxyHostsForGlobal()

	return block, nil
}

func (s *SecurityService) RemoveGlobalURIBlockRule(ctx context.Context, ruleID string) (string, error) {
	// Get the rule info before deletion for audit log
	existing, _ := s.uriBlockRepo.GetGlobalURIBlock(ctx)
	var removedPattern string
	if existing != nil {
		for _, rule := range existing.Rules {
			if rule.ID == ruleID {
				removedPattern = rule.Pattern
				break
			}
		}
	}

	if err := s.uriBlockRepo.RemoveGlobalRule(ctx, ruleID); err != nil {
		return "", fmt.Errorf("failed to remove global URI block rule: %w", err)
	}

	// Sync all proxy host configs in background
	go s.syncAllProxyHostsForGlobal()

	return removedPattern, nil
}

func (s *SecurityService) syncAllProxyHostsForGlobal() {
	ctx := context.Background()
	if s.proxyHostService != nil {
		_ = s.proxyHostService.SyncAllConfigs(ctx)
	}
}

// cacheURIBlock updates the URI block cache in Redis.
func (s *SecurityService) cacheURIBlock(ctx context.Context, proxyHostID string, uriBlock *model.URIBlock) {
	if s.redisCache == nil || uriBlock == nil {
		return
	}

	patterns := make([]cache.URIBlockPattern, 0, len(uriBlock.Rules))
	for _, rule := range uriBlock.Rules {
		if rule.Enabled {
			patterns = append(patterns, cache.URIBlockPattern{
				Pattern:   rule.Pattern,
				MatchType: string(rule.MatchType),
				Enabled:   rule.Enabled,
			})
		}
	}

	entry := &cache.URIBlockEntry{
		HostID:          proxyHostID,
		Enabled:         uriBlock.Enabled,
		AllowPrivateIPs: uriBlock.AllowPrivateIPs,
		ExceptionIPs:    uriBlock.ExceptionIPs,
		Patterns:        patterns,
	}

	s.redisCache.SetURIBlock(ctx, proxyHostID, entry)
}
