package cliproxy

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	log "github.com/sirupsen/logrus"
)

func (s *Service) applyConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, true)
}

func (s *Service) applyWatcherConfigUpdate(newCfg *config.Config) {
	s.applyConfigUpdateWithAuthSynthesis(context.Background(), newCfg, false)
}

type configCommit struct {
	cfg                  *config.Config
	sequence             uint64
	sessionStoreMigrated bool
}

type routingRuntimeState struct {
	strategy                 string
	sessionAffinity          bool
	sessionAffinityStrict    bool
	sessionAffinityTTL       time.Duration
	sessionAffinityPersist   bool
	sessionAffinityStorePath string
}

func normalizedRoutingRuntimeState(cfg *config.Config) routingRuntimeState {
	state := routingRuntimeState{
		strategy:           "round-robin",
		sessionAffinityTTL: time.Hour,
	}
	if cfg == nil {
		return state
	}

	switch strings.ToLower(strings.TrimSpace(cfg.Routing.Strategy)) {
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		state.strategy = "weighted-round-robin"
	case "fill-first", "fillfirst", "ff":
		state.strategy = "fill-first"
	}
	state.sessionAffinity = cfg.Routing.SessionAffinity
	state.sessionAffinityStrict = cfg.Routing.SessionAffinityStrict
	state.sessionAffinityPersist = cfg.Routing.SessionAffinityPersist ||
		(state.sessionAffinity && state.sessionAffinityStrict)
	if ttl := strings.TrimSpace(cfg.Routing.SessionAffinityTTL); ttl != "" {
		if parsed, errParse := time.ParseDuration(ttl); errParse == nil && parsed > 0 {
			state.sessionAffinityTTL = parsed
		}
	}
	if state.sessionAffinityPersist {
		state.sessionAffinityStorePath = strings.TrimSpace(cfg.Routing.SessionAffinityStore)
		if state.sessionAffinityStorePath == "" {
			state.sessionAffinityStorePath = filepath.Join(strings.TrimSpace(cfg.AuthDir), ".session-affinity.sab")
		}
	}
	return state
}

func newBaseRoutingSelector(state routingRuntimeState) coreauth.Selector {
	var selector coreauth.Selector
	switch state.strategy {
	case "weighted-round-robin":
		selector = &coreauth.WeightedRoundRobinSelector{}
	case "fill-first":
		selector = &coreauth.FillFirstSelector{}
	default:
		selector = &coreauth.RoundRobinSelector{}
	}
	return selector
}

func newRoutingSelector(state routingRuntimeState) coreauth.Selector {
	selector := newBaseRoutingSelector(state)
	if state.sessionAffinity {
		var store coreauth.SessionBindingStore
		if state.sessionAffinityPersist {
			store = coreauth.NewFileSessionBindingStore(state.sessionAffinityStorePath)
		}
		selector = coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
			Fallback: selector,
			Strict:   state.sessionAffinityStrict,
			TTL:      state.sessionAffinityTTL,
			Store:    store,
		})
	}
	return selector
}

func canReuseSessionAffinityCache(previous *routingRuntimeState, next routingRuntimeState) bool {
	return previous != nil && previous.sessionAffinity && next.sessionAffinity &&
		previous.sessionAffinityPersist == next.sessionAffinityPersist &&
		previous.sessionAffinityStorePath == next.sessionAffinityStorePath
}

func requiresSessionAffinityStoreMigration(previous *routingRuntimeState, next routingRuntimeState) bool {
	return previous != nil && previous.sessionAffinity && next.sessionAffinity && next.sessionAffinityStrict &&
		(!previous.sessionAffinityStrict || previous.sessionAffinityPersist != next.sessionAffinityPersist ||
			previous.sessionAffinityStorePath != next.sessionAffinityStorePath)
}

func (s *Service) applyConfigUpdateWithAuthSynthesis(ctx context.Context, newCfg *config.Config, synthesizeConfigAuths bool) bool {
	if s == nil {
		return false
	}
	s.configTransitionMu.Lock()
	defer s.configTransitionMu.Unlock()
	if newCfg == nil {
		s.cfgMu.RLock()
		newCfg = s.cfg
		s.cfgMu.RUnlock()
	}
	if newCfg == nil || newCfg.ValidateCredentialWeights() != nil {
		return false
	}
	nextRoutingState := normalizedRoutingRuntimeState(newCfg)
	migrated := false
	if requiresSessionAffinityStoreMigration(s.appliedRoutingState, nextRoutingState) {
		if s.coreManager == nil {
			return false
		}
		store := coreauth.NewFileSessionBindingStore(nextRoutingState.sessionAffinityStorePath)
		if errMigrate := s.coreManager.MigrateAndReconfigureSessionAffinitySelector(
			store,
			newBaseRoutingSelector(nextRoutingState),
			nextRoutingState.sessionAffinityStrict,
			nextRoutingState.sessionAffinityTTL,
		); errMigrate != nil {
			log.Errorf("failed to migrate strict session affinity store before config commit: %v", errMigrate)
			return false
		}
		migrated = true
	}
	commit := s.commitConfigUpdate(newCfg)
	if commit.cfg == nil {
		return false
	}
	commit.sessionStoreMigrated = migrated
	return s.applyConfigRuntime(ctx, commit, synthesizeConfigAuths)
}

// commitConfigUpdate applies only in-memory configuration state. Runtime work that
// may block on plugins, models, storage, or networking is deliberately deferred.
func (s *Service) commitConfigUpdate(newCfg *config.Config) configCommit {
	if s == nil {
		return configCommit{}
	}

	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()

	if newCfg == nil {
		s.cfgMu.RLock()
		newCfg = s.cfg
		s.cfgMu.RUnlock()
	}
	if newCfg == nil {
		return configCommit{}
	}
	if errValidate := newCfg.ValidateCredentialWeights(); errValidate != nil {
		log.WithError(errValidate).Warn("rejected config update with invalid credential weights")
		return configCommit{}
	}

	s.cfgMu.Lock()
	s.cfg = newCfg
	s.cfgMu.Unlock()
	s.configSequence++
	return configCommit{cfg: newCfg, sequence: s.configSequence}
}

func (s *Service) configCommitCurrent(commit configCommit) bool {
	if s == nil || commit.sequence == 0 {
		return false
	}
	s.configUpdateMu.Lock()
	current := s.configSequence == commit.sequence
	s.configUpdateMu.Unlock()
	return current
}

func (s *Service) applyConfigRuntime(ctx context.Context, commit configCommit, synthesizeConfigAuths bool) bool {
	cfg := commit.cfg
	if s == nil || cfg == nil {
		return false
	}
	s.configRuntimeMu.Lock()
	defer s.configRuntimeMu.Unlock()
	if !s.configCommitCurrent(commit) {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	if !s.applyManagerConfig(ctx, commit) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.applyPprofConfigContext(ctx, cfg) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if !s.updateServerClientsContext(ctx, cfg) {
		return false
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}

	registrationCtx := coreauth.WithSkipPersist(ctx)
	s.syncPluginRuntimeConfigForConfig(registrationCtx, cfg)
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	var auths []*coreauth.Auth
	if s.coreManager != nil {
		auths = s.coreManager.List()
	}
	s.registerAvailableExecutors(registrationCtx, executorRegistrationOptions{
		includeBaseline:   cfg.Home.Enabled,
		forceReplaceAuths: true,
		auths:             auths,
	})
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if synthesizeConfigAuths {
		s.registerConfigAPIKeyAuths(registrationCtx, cfg)
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	if s.coreManager != nil && !cfg.Home.Enabled && cfg.SaveCooldownStatus {
		if errRestoreCooldown := s.coreManager.RestoreCooldownStates(registrationCtx); errRestoreCooldown != nil && ctx.Err() == nil {
			log.Warnf("failed to restore cooldown state after config update: %v", errRestoreCooldown)
		}
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	s.syncPluginModelRuntime(registrationCtx)
	return ctx.Err() == nil
}

func (s *Service) applyManagerConfig(ctx context.Context, commit configCommit) bool {
	if s == nil || s.coreManager == nil || commit.cfg == nil {
		return s != nil && commit.cfg != nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if errContext := ctx.Err(); errContext != nil {
		return false
	}
	routingState := normalizedRoutingRuntimeState(commit.cfg)
	if s.appliedRoutingState == nil || *s.appliedRoutingState != routingState {
		reused := false
		if requiresSessionAffinityStoreMigration(s.appliedRoutingState, routingState) {
			if !commit.sessionStoreMigrated {
				store := coreauth.NewFileSessionBindingStore(routingState.sessionAffinityStorePath)
				if errMigrate := s.coreManager.MigrateAndReconfigureSessionAffinitySelector(
					store,
					newBaseRoutingSelector(routingState),
					routingState.sessionAffinityStrict,
					routingState.sessionAffinityTTL,
				); errMigrate != nil {
					log.Errorf("failed to migrate strict session affinity store: %v", errMigrate)
					return false
				}
			}
			reused = commit.sessionStoreMigrated || s.coreManager.ReconfigureSessionAffinitySelector(
				newBaseRoutingSelector(routingState), routingState.sessionAffinityStrict, routingState.sessionAffinityTTL)
			if !reused {
				log.Error("failed to reconfigure strict session affinity selector after store migration")
				return false
			}
		}
		if canReuseSessionAffinityCache(s.appliedRoutingState, routingState) {
			reused = reused || s.coreManager.ReconfigureSessionAffinitySelector(
				newBaseRoutingSelector(routingState),
				routingState.sessionAffinityStrict,
				routingState.sessionAffinityTTL,
			)
		}
		if !reused {
			s.coreManager.SetSelector(newRoutingSelector(routingState))
		}
		s.appliedRoutingState = &routingState
	}
	s.applyRetryConfig(commit.cfg)
	store := s.resolveCooldownStateStore(commit.cfg)
	if !s.coreManager.ApplyConfigWithCooldownStateStore(ctx, commit.cfg, store) {
		return false
	}
	s.coreManager.SetOAuthModelAlias(commit.cfg.OAuthModelAlias)
	return true
}

func (s *Service) updateServerClientsContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	if s.updateServerClientsContextFn != nil {
		return s.updateServerClientsContextFn(ctx, cfg)
	}
	if s.server == nil {
		return true
	}
	return s.server.UpdateClientsContext(ctx, cfg)
}

func (s *Service) reloadConfigFromWatcher() bool {
	if s == nil || s.watcher == nil {
		return false
	}
	return s.watcher.ReloadConfigIfChanged()
}

func (s *Service) registerConfigAPIKeyAuths(ctx context.Context, cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	configSynth := synthesizer.NewConfigSynthesizer()
	auths, errSynthesize := configSynth.Synthesize(&synthesizer.SynthesisContext{
		Config:      cfg,
		Now:         time.Now(),
		IDGenerator: synthesizer.NewStableIDGenerator(),
	})
	if errSynthesize != nil {
		log.Warnf("failed to synthesize config API key auths: %v", errSynthesize)
		return
	}

	registrationCtx := coreauth.WithDeferredAPIKeyModelAliasRebuild(ctx)
	tasks := make([]modelRegistrationTask, 0, len(auths))
	needsAliasRebuild := false
	for _, auth := range auths {
		if !coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}
		prepared := s.prepareCoreAuthForModelRegistration(registrationCtx, auth)
		if prepared == nil {
			continue
		}
		needsAliasRebuild = true
		authForRegistration := prepared
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhaseConfigAPIKey,
			category: modelRegistrationCategory(authForRegistration),
			run: func(compatCache *openAICompatibilityRegistrationCache) {
				s.completeModelRegistrationForAuthWithCache(registrationCtx, authForRegistration, compatCache)
			},
		})
	}
	if needsAliasRebuild {
		s.coreManager.RefreshAPIKeyModelAlias()
	}
	s.runModelRegistrationTasks(registrationCtx, tasks)
}

func forceHomeRuntimeConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cfg.APIKeys = nil
	cfg.UsageStatisticsEnabled = true
	cfg.DisableCooling = true
	cfg.SaveCooldownStatus = false
	cfg.WebsocketAuth = false
	cfg.RemoteManagement.AllowRemote = false
	cfg.RemoteManagement.DisableControlPanel = true
	cfg.Plugins.StoreAuth = nil
}
