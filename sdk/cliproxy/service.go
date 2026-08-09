// Package cliproxy provides the core service implementation for the CLI Proxy API.
// It includes service lifecycle management, authentication handling, file watching,
// and integration with various AI service providers through a unified interface.
package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/api"
	managementHandlers "github.com/router-for-me/CLIProxyAPI/v7/internal/api/handlers/management"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/home"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/pluginhost"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/redisqueue"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/quota"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/diff"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/watcher/synthesizer"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/wsrelay"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	log "github.com/sirupsen/logrus"
)

// Service wraps the proxy server lifecycle so external programs can embed the CLI proxy.
// It manages the complete lifecycle including authentication, file watching, HTTP server,
// and integration with various AI service providers.
type Service struct {
	// cfg holds the current application configuration.
	cfg *config.Config

	// cfgMu protects concurrent access to the configuration.
	cfgMu sync.RWMutex

	// configUpdateMu serializes config updates across watcher + home.
	configUpdateMu sync.Mutex

	// configPath is the path to the configuration file.
	configPath string

	// tokenProvider handles loading token-based clients.
	tokenProvider TokenClientProvider

	// apiKeyProvider handles loading API key-based clients.
	apiKeyProvider APIKeyClientProvider

	// watcherFactory creates file watcher instances.
	watcherFactory WatcherFactory

	// hooks provides lifecycle callbacks.
	hooks Hooks

	// serverOptions contains additional server configuration options.
	serverOptions []api.ServerOption

	// server is the HTTP API server instance.
	server *api.Server

	// pprofServer manages the optional pprof HTTP debug server.
	pprofServer *pprofServer

	// serverErr channel for server startup/shutdown errors.
	serverErr chan error

	// watcher handles file system monitoring.
	watcher *WatcherWrapper

	// watcherCancel cancels the watcher context.
	watcherCancel context.CancelFunc

	// authUpdates channel for authentication updates.
	authUpdates chan watcher.AuthUpdate

	// authQueueStop cancels the auth update queue processing.
	authQueueStop context.CancelFunc

	// authManager handles legacy authentication operations.
	authManager *sdkAuth.Manager

	// accessManager handles request authentication providers.
	accessManager *sdkaccess.Manager

	// coreManager handles core authentication and execution.
	coreManager *coreauth.Manager

	// pluginHost owns dynamic plugin lifecycle and runtime capability adapters.
	pluginHost *pluginhost.Host

	// quotaFetcher loads wham/usage snapshots for codex auths. Shared with
	// quotaRefresher; nil when an external caller supplied their own
	// coreManager (and thus owns the quota subsystem too).
	quotaFetcher *quota.CodexWhamFetcher

	// quotaSelector is the inner LeastRemainingQuotaSelector that owns the
	// quota cache. quotaRefresher pushes wham/usage snapshots here on a
	// background cycle so Pick stays off the network.
	quotaSelector *coreauth.LeastRemainingQuotaSelector

	// quotaRefresher periodically refreshes quotaSelector's cache for
	// every codex auth. Started in Run, stopped in Shutdown. Replaced
	// from applyConfigUpdate when the selector chain is rebuilt.
	quotaRefresher *quota.Refresher

	// xaiBilling polls grok /v1/billing for xai auths and serves cached
	// monthly-usage snapshots to the management UI. Display-only; entirely
	// separate from the codex quota selector. Lifecycle mirrors quotaRefresher.
	xaiBilling *quota.XAIBillingPoller

	// shutdownOnce ensures shutdown is called only once.
	shutdownOnce sync.Once

	// wsGateway manages websocket Gemini providers.
	wsGateway *wsrelay.Manager

	homeClient       *home.Client
	homeCancel       context.CancelFunc
	homeLogForwarder *logging.HomeAppLogForwarder
}

const modelRegistrationMaxWorkersPerCategory = 5

const (
	modelRegistrationPhaseConfigAPIKey = iota
	modelRegistrationPhaseOther
)

type modelRegistrationTask struct {
	phase    int
	category string
	run      func()
}

type executorRegistrationOptions struct {
	includeBaseline   bool
	includePlugins    bool
	forceReplaceAuths bool
	auths             []*coreauth.Auth
}

var registerPluginExecutors = func(host *pluginhost.Host, manager *coreauth.Manager) {
	if host == nil || manager == nil {
		return
	}
	host.RegisterExecutors(manager, registry.GetGlobalRegistry())
}

// RegisterUsagePlugin registers a usage plugin on the global usage manager.
// This allows external code to monitor API usage and token consumption.
//
// Parameters:
//   - plugin: The usage plugin to register
func (s *Service) RegisterUsagePlugin(plugin usage.Plugin) {
	usage.RegisterPlugin(plugin)
}

func (s *Service) registerPluginAuthParser() {
	var parser PluginAuthParser
	if s != nil && s.pluginHost != nil {
		parser = s.pluginHost
	}
	sdkAuth.RegisterPluginAuthParser(parser)
	if s != nil && s.watcher != nil {
		s.watcher.SetPluginAuthParser(parser)
	}
}

func (s *Service) syncPluginRuntime(ctx context.Context) {
	if !s.syncPluginRuntimeConfig(ctx) {
		return
	}
	s.syncPluginModelRuntime(ctx)
}

func (s *Service) syncPluginRuntimeConfig(ctx context.Context) bool {
	if s == nil {
		sdkAuth.RegisterPluginAuthParser(nil)
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()

	if s.pluginHost != nil {
		s.pluginHost.ApplyConfig(ctx, cfg)
	}
	if s.coreManager != nil {
		s.coreManager.SetPluginScheduler(s.pluginHost)
	}
	s.registerPluginAuthParser()
	if s.pluginHost == nil {
		return false
	}
	s.pluginHost.RegisterFrontendAuthProviders()
	if s.accessManager != nil {
		s.accessManager.SetProviders(sdkaccess.RegisteredProviders())
	}
	s.pluginHost.RegisterUsagePlugins()
	sdktranslator.SetPluginHooks(s.pluginHost)
	if s.server != nil {
		s.server.RefreshPluginManagementRoutes()
	}
	return true
}

func (s *Service) syncPluginModelRuntime(ctx context.Context) {
	if s == nil || s.pluginHost == nil || s.coreManager == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.pluginHost.RegisterModels(ctx, registry.GetGlobalRegistry())
	s.registerAvailableExecutors(ctx, executorRegistrationOptions{
		includeBaseline:   s.cfg != nil && s.cfg.Home.Enabled,
		includePlugins:    true,
		forceReplaceAuths: true,
		auths:             s.coreManager.List(),
	})
	s.refreshPluginModelRegistrations(ctx)
	s.coreManager.RefreshSchedulerAll()
}

func (s *Service) refreshPluginModelRegistrations(ctx context.Context) {
	if s == nil || s.pluginHost == nil || s.coreManager == nil {
		return
	}
	s.registerModelsForAuthBatch(ctx, s.coreManager.List())
}

func (s *Service) registerModelsForAuthBatch(ctx context.Context, auths []*coreauth.Auth) {
	if s == nil || s.coreManager == nil || len(auths) == 0 {
		return
	}
	tasks := make([]modelRegistrationTask, 0, len(auths))
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		authForRegistration := auth.Clone()
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhase(authForRegistration),
			category: modelRegistrationCategory(authForRegistration),
			run: func() {
				s.completeModelRegistrationForAuth(ctx, authForRegistration)
			},
		})
	}
	s.runModelRegistrationTasks(ctx, tasks)
}

func (s *Service) runModelRegistrationTasks(ctx context.Context, tasks []modelRegistrationTask) {
	if len(tasks) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	configAPIKeyTasks := make([]modelRegistrationTask, 0)
	otherTasks := make([]modelRegistrationTask, 0)
	for _, task := range tasks {
		if task.phase == modelRegistrationPhaseConfigAPIKey {
			configAPIKeyTasks = append(configAPIKeyTasks, task)
			continue
		}
		otherTasks = append(otherTasks, task)
	}

	s.runModelRegistrationTaskPhase(ctx, configAPIKeyTasks)
	s.runModelRegistrationTaskPhase(ctx, otherTasks)
}

func (s *Service) runModelRegistrationTaskPhase(ctx context.Context, tasks []modelRegistrationTask) {
	if len(tasks) == 0 {
		return
	}

	grouped := make(map[string][]modelRegistrationTask)
	order := make([]string, 0)
	for _, task := range tasks {
		if task.run == nil {
			continue
		}
		category := strings.ToLower(strings.TrimSpace(task.category))
		if category == "" {
			category = "unknown"
		}
		if _, exists := grouped[category]; !exists {
			order = append(order, category)
		}
		grouped[category] = append(grouped[category], task)
	}

	var wg sync.WaitGroup
	for _, category := range order {
		group := grouped[category]
		workers := len(group)
		if workers > modelRegistrationMaxWorkersPerCategory {
			workers = modelRegistrationMaxWorkersPerCategory
		}
		if workers <= 0 {
			continue
		}

		taskCh := make(chan modelRegistrationTask)
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for task := range taskCh {
					select {
					case <-ctx.Done():
						return
					default:
					}
					task.run()
				}
			}()
		}
		go func(group []modelRegistrationTask) {
			defer close(taskCh)
			for _, task := range group {
				select {
				case <-ctx.Done():
					return
				case taskCh <- task:
				}
			}
		}(group)
	}
	wg.Wait()
}

func modelRegistrationPhase(auth *coreauth.Auth) int {
	if isConfigAPIKeyAuth(auth) {
		return modelRegistrationPhaseConfigAPIKey
	}
	return modelRegistrationPhaseOther
}

func isConfigAPIKeyAuth(auth *coreauth.Auth) bool {
	if auth == nil || auth.Attributes == nil {
		return false
	}
	if strings.TrimSpace(auth.Attributes["api_key"]) == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(auth.Attributes["source"])), "config:")
}

func modelRegistrationCategory(auth *coreauth.Auth) string {
	if auth == nil {
		return "unknown"
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if compatProviderKey, _, compatDetected := openAICompatInfoFromAuth(auth); compatDetected {
		if compatProviderKey != "" {
			provider = compatProviderKey
		} else {
			provider = "openai-compatibility"
		}
	}
	if provider == "" {
		provider = "unknown"
	}

	authKind := strings.ToLower(strings.TrimSpace(auth.Attributes["auth_kind"]))
	if authKind == "" {
		if kind, _ := auth.AccountInfo(); strings.EqualFold(kind, "api_key") {
			authKind = "apikey"
		}
	}
	if authKind == "" {
		return provider
	}
	return provider + ":" + authKind
}

func (s *Service) registerModelRefreshCallback() {
	// Register callback for startup and periodic model catalog refresh.
	// When remote model definitions change, re-register models for affected providers.
	// This intentionally rebuilds per-auth model availability from the latest catalog
	// snapshot instead of preserving prior registry suppression state.
	registry.SetModelRefreshCallback(func(changedProviders []string) {
		if s == nil || s.coreManager == nil || len(changedProviders) == 0 {
			return
		}

		providerSet := make(map[string]bool, len(changedProviders))
		for _, p := range changedProviders {
			providerSet[strings.ToLower(strings.TrimSpace(p))] = true
		}

		auths := s.coreManager.List()
		refreshed := 0
		var refreshedMu sync.Mutex
		tasks := make([]modelRegistrationTask, 0, len(auths))
		for _, item := range auths {
			if item == nil || item.ID == "" {
				continue
			}
			auth, ok := s.coreManager.GetByID(item.ID)
			if !ok || auth == nil || auth.Disabled {
				continue
			}
			provider := strings.ToLower(strings.TrimSpace(auth.Provider))
			if !providerSet[provider] {
				continue
			}
			authForRefresh := auth
			tasks = append(tasks, modelRegistrationTask{
				phase:    modelRegistrationPhase(authForRefresh),
				category: modelRegistrationCategory(authForRefresh),
				run: func() {
					if s.refreshModelRegistrationForAuth(authForRefresh) {
						refreshedMu.Lock()
						refreshed++
						refreshedMu.Unlock()
					}
				},
			})
		}
		s.runModelRegistrationTasks(context.Background(), tasks)

		if refreshed > 0 {
			log.Infof("re-registered models for %d auth(s) due to model catalog changes: %v", refreshed, changedProviders)
		}
	})
}

// sessionAffinityCachePath returns the on-disk path used to persist the
// session-affinity selector's bindings. The cache lives next to the auth
// token files (cfg.AuthDir) so it shares the same protection as the
// credentials themselves. Returns "" when no AuthDir is configured, which
// disables persistence and keeps the legacy in-memory-only behaviour.
func sessionAffinityCachePath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	dir := strings.TrimSpace(cfg.AuthDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "session-affinity-cache.json")
}

// rrCursorPath returns the on-disk path used to persist the round-robin
// selector's cursor map. Without this, every restart wipes the cursor and
// re-seeds randomly, which combined with the persisted session-affinity
// cache occasionally causes a freshly-bound new window to land on the same
// auth as an existing persisted binding (N windows → fewer than N accounts).
func rrCursorPath(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	dir := strings.TrimSpace(cfg.AuthDir)
	if dir == "" {
		return ""
	}
	return filepath.Join(dir, "round-robin-cursor.json")
}

// newDefaultAuthManager creates a default authentication manager with all supported providers.
func newDefaultAuthManager() *sdkAuth.Manager {
	return sdkAuth.NewManager(
		sdkAuth.GetTokenStore(),
		sdkAuth.NewGeminiAuthenticator(),
		sdkAuth.NewCodexAuthenticator(),
		sdkAuth.NewClaudeAuthenticator(),
		sdkAuth.NewXAIAuthenticator(),
	)
}

func (s *Service) ensureAuthUpdateQueue(ctx context.Context) {
	if s == nil {
		return
	}
	if s.authUpdates == nil {
		s.authUpdates = make(chan watcher.AuthUpdate, 256)
	}
	if s.authQueueStop != nil {
		return
	}
	queueCtx, cancel := context.WithCancel(ctx)
	s.authQueueStop = cancel
	go s.consumeAuthUpdates(queueCtx)
}

func (s *Service) consumeAuthUpdates(ctx context.Context) {
	ctx = coreauth.WithSkipPersist(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case update, ok := <-s.authUpdates:
			if !ok {
				return
			}
			updates := []watcher.AuthUpdate{update}
		labelDrain:
			for {
				select {
				case nextUpdate := <-s.authUpdates:
					updates = append(updates, nextUpdate)
				default:
					break labelDrain
				}
			}
			s.handleAuthUpdates(ctx, updates)
		}
	}
}

func (s *Service) emitAuthUpdate(ctx context.Context, update watcher.AuthUpdate) {
	if s == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.watcher != nil && s.watcher.DispatchRuntimeAuthUpdate(update) {
		return
	}
	if s.authUpdates != nil {
		select {
		case s.authUpdates <- update:
			return
		default:
			log.Debugf("auth update queue saturated, applying inline action=%v id=%s", update.Action, update.ID)
		}
	}
	s.handleAuthUpdate(ctx, update)
}

func (s *Service) handleAuthUpdate(ctx context.Context, update watcher.AuthUpdate) {
	s.handleAuthUpdates(ctx, []watcher.AuthUpdate{update})
}

func (s *Service) handleAuthUpdates(ctx context.Context, updates []watcher.AuthUpdate) {
	if s == nil {
		return
	}
	updates = coalesceAuthUpdates(updates)
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if cfg == nil || s.coreManager == nil {
		return
	}

	tasks := make([]modelRegistrationTask, 0, len(updates))
	needsPluginSync := false
	for _, update := range updates {
		switch update.Action {
		case watcher.AuthUpdateActionAdd, watcher.AuthUpdateActionModify:
			if update.Auth == nil || update.Auth.ID == "" {
				continue
			}
			auth := s.prepareCoreAuthForModelRegistration(ctx, update.Auth)
			if auth == nil {
				continue
			}
			authForRegistration := auth
			tasks = append(tasks, modelRegistrationTask{
				phase:    modelRegistrationPhase(authForRegistration),
				category: modelRegistrationCategory(authForRegistration),
				run: func() {
					s.completeModelRegistrationForAuth(ctx, authForRegistration)
				},
			})
			needsPluginSync = true
		case watcher.AuthUpdateActionDelete:
			id := update.ID
			if id == "" && update.Auth != nil {
				id = update.Auth.ID
			}
			if id == "" {
				continue
			}
			s.applyCoreAuthRemoval(ctx, id)
		default:
			log.Debugf("received unknown auth update action: %v", update.Action)
		}
	}

	s.runModelRegistrationTasks(ctx, tasks)
	if needsPluginSync {
		s.syncPluginRuntime(ctx)
	}
}

func coalesceAuthUpdates(updates []watcher.AuthUpdate) []watcher.AuthUpdate {
	if len(updates) <= 1 {
		return updates
	}
	order := make([]string, 0, len(updates))
	byID := make(map[string]watcher.AuthUpdate, len(updates))
	unkeyed := make([]watcher.AuthUpdate, 0)
	for _, update := range updates {
		id := authUpdateID(update)
		if id == "" {
			unkeyed = append(unkeyed, update)
			continue
		}
		if _, exists := byID[id]; !exists {
			order = append(order, id)
		}
		byID[id] = update
	}
	if len(byID) == 0 {
		return unkeyed
	}
	out := make([]watcher.AuthUpdate, 0, len(byID)+len(unkeyed))
	for _, id := range order {
		out = append(out, byID[id])
	}
	out = append(out, unkeyed...)
	return out
}

func authUpdateID(update watcher.AuthUpdate) string {
	if strings.TrimSpace(update.ID) != "" {
		return strings.TrimSpace(update.ID)
	}
	if update.Auth != nil {
		return strings.TrimSpace(update.Auth.ID)
	}
	return ""
}

func (s *Service) ensureWebsocketGateway() {
	if s == nil {
		return
	}
	if s.wsGateway != nil {
		return
	}
	opts := wsrelay.Options{
		Path:           "/v1/ws",
		OnConnected:    s.wsOnConnected,
		OnDisconnected: s.wsOnDisconnected,
		LogDebugf:      log.Debugf,
		LogInfof:       log.Infof,
		LogWarnf:       log.Warnf,
	}
	s.wsGateway = wsrelay.NewManager(opts)
}

func (s *Service) wsOnConnected(channelID string) {
	if s == nil || channelID == "" {
		return
	}
	if !strings.HasPrefix(strings.ToLower(channelID), "aistudio-") {
		return
	}
	if s.coreManager != nil {
		if existing, ok := s.coreManager.GetByID(channelID); ok && existing != nil {
			if !existing.Disabled && existing.Status == coreauth.StatusActive {
				return
			}
		}
	}
	now := time.Now().UTC()
	auth := &coreauth.Auth{
		ID:         channelID,  // keep channel identifier as ID
		Provider:   "aistudio", // logical provider for switch routing
		Label:      channelID,  // display original channel id
		Status:     coreauth.StatusActive,
		CreatedAt:  now,
		UpdatedAt:  now,
		Attributes: map[string]string{"runtime_only": "true"},
		Metadata:   map[string]any{"email": channelID}, // metadata drives logging and usage tracking
	}
	log.Infof("websocket provider connected: %s", channelID)
	s.emitAuthUpdate(context.Background(), watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionAdd,
		ID:     auth.ID,
		Auth:   auth,
	})
}

func (s *Service) wsOnDisconnected(channelID string, reason error) {
	if s == nil || channelID == "" {
		return
	}
	if reason != nil {
		if strings.Contains(reason.Error(), "replaced by new connection") {
			log.Infof("websocket provider replaced: %s", channelID)
			return
		}
		log.Warnf("websocket provider disconnected: %s (%v)", channelID, reason)
	} else {
		log.Infof("websocket provider disconnected: %s", channelID)
	}
	ctx := context.Background()
	s.emitAuthUpdate(ctx, watcher.AuthUpdate{
		Action: watcher.AuthUpdateActionDelete,
		ID:     channelID,
	})
}

func (s *Service) applyCoreAuthAddOrUpdate(ctx context.Context, auth *coreauth.Auth) {
	auth = s.prepareCoreAuthForModelRegistration(ctx, auth)
	if auth == nil {
		return
	}
	s.completeModelRegistrationForAuth(ctx, auth)
	s.syncPluginRuntime(ctx)
}

func (s *Service) prepareCoreAuthForModelRegistration(ctx context.Context, auth *coreauth.Auth) *coreauth.Auth {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return nil
	}
	auth = auth.Clone()
	s.ensureExecutorsForAuth(auth)

	// IMPORTANT: Update coreManager FIRST, before model registration.
	// This ensures that configuration changes (proxy_url, prefix, etc.) take effect
	// immediately for API calls, rather than waiting for model registration to complete.
	op := "register"
	var err error
	if existing, ok := s.coreManager.GetByID(auth.ID); ok {
		auth.CreatedAt = existing.CreatedAt
		if !existing.Disabled && existing.Status != coreauth.StatusDisabled && !auth.Disabled && auth.Status != coreauth.StatusDisabled {
			auth.LastRefreshedAt = existing.LastRefreshedAt
			auth.NextRefreshAfter = existing.NextRefreshAfter
			if len(auth.ModelStates) == 0 && len(existing.ModelStates) > 0 {
				auth.ModelStates = existing.ModelStates
			}
		}
		op = "update"
		_, err = s.coreManager.Update(ctx, auth)
	} else {
		_, err = s.coreManager.Register(ctx, auth)
	}
	if err != nil {
		log.Errorf("failed to %s auth %s: %v", op, auth.ID, err)
		current, ok := s.coreManager.GetByID(auth.ID)
		if !ok || current.Disabled {
			GlobalModelRegistry().UnregisterClient(auth.ID)
			return nil
		}
		auth = current
	}
	return auth
}

func (s *Service) completeModelRegistrationForAuth(ctx context.Context, auth *coreauth.Auth) {
	if s == nil || s.coreManager == nil || auth == nil || auth.ID == "" {
		return
	}
	s.registerModelsForAuth(ctx, auth)
	s.coreManager.ReconcileRegistryModelStates(ctx, auth.ID)

	// Refresh the scheduler entry so that the auth's supportedModelSet is rebuilt
	// from the now-populated global model registry. Without this, newly added auths
	// have an empty supportedModelSet (because Register/Update upserts into the
	// scheduler before registerModelsForAuth runs) and are invisible to the scheduler.
	s.coreManager.RefreshSchedulerEntry(auth.ID)

	// Kick the background refresher so this auth gets a fresh wham/usage
	// snapshot without waiting for the next periodic tick. Important for
	// re-login flows where the user expects the credential to be usable
	// (and quota-ranked) immediately, not 30 seconds later.
	if s.quotaRefresher != nil {
		s.quotaRefresher.Trigger(auth.ID)
	}
}

func (s *Service) applyCoreAuthRemoval(ctx context.Context, id string) {
	if s == nil || id == "" {
		return
	}
	if s.coreManager == nil {
		return
	}
	id = strings.TrimSpace(id)
	var provider string
	if existing, ok := s.coreManager.GetByID(id); ok && existing != nil {
		provider = strings.TrimSpace(existing.Provider)
	}
	GlobalModelRegistry().UnregisterClient(id)
	s.coreManager.Remove(ctx, id)
	if strings.EqualFold(provider, "codex") {
		executor.CloseCodexWebsocketSessionsForAuthID(id, "auth_removed")
	}
	s.syncPluginRuntime(ctx)
}

// startQuotaRefresher constructs and starts the background quota
// refresher. Safe to call when the service has no quota subsystem (e.g.
// SDK callers that supplied their own coreManager) — it becomes a
// no-op. Existing refreshers are stopped before being replaced so the
// method is also safe to call after applyConfigUpdate rebuilds the
// selector chain.
func (s *Service) startQuotaRefresher(ctx context.Context) {
	if s == nil || s.quotaFetcher == nil || s.quotaSelector == nil || s.coreManager == nil {
		return
	}
	if s.quotaRefresher != nil {
		s.quotaRefresher.Stop()
		s.quotaRefresher = nil
	}
	// The refresher reads through s.coreManager so it automatically
	// observes auth additions, removals, and re-logins without needing
	// its own subscription. The selector is captured here; if a config
	// reload swaps it (applyConfigUpdate), this refresher is stopped and
	// replaced by a new one bound to the new selector.
	selector := s.quotaSelector
	mgr := s.coreManager
	// Mirror every pushed snapshot into the monitor's quota history so the
	// operator UI can draw a usage curve (and see what an account peaked at
	// before a window reset). Purely observational — the selector still
	// receives the snapshot exactly as before.
	pushSnapshot := func(authID string, snap coreauth.QuotaSnapshot) {
		selector.PushSnapshot(authID, snap)
		if s.server != nil {
			s.server.RecordQuotaSample(authID, snap.UsedPercentPrimary, snap.UsedPercentSecondary, snap.LimitReached, snap.ResetAtPrimary)
		}
	}
	refresher := quota.NewRefresher(
		s.quotaFetcher,
		func() []*coreauth.Auth { return mgr.List() },
		pushSnapshot,
		// Auto-clear stale cooldown markers when wham confirms the
		// auth is healthy upstream. Bridges the gap between the
		// conductor's "recover on next success call" path and the
		// reality that a stuck auth may be filtered out of the
		// candidate pool, never seeing a success to trigger the
		// existing recovery. Without this, an auth like
		// t.yamada.takashi can sit on a 2h-stale `quota_exceeded`
		// marker indefinitely because the next-success path can't
		// fire.
		quota.WithStaleCooldownClearer(func(ctx context.Context, authID string) error {
			// Skip auto-clear when the operator has set a manual
			// cooldown that has not yet expired — the whole point of
			// the manual entry is to hold an auth out of rotation
			// even when wham/usage is returning bogus 100%-available
			// data. Once NextRecoverAt passes, the operator's
			// intended duration is fulfilled and the refresher can
			// clear normally.
			if existing, ok := mgr.GetByID(authID); ok && existing != nil {
				if existing.Quota.Reason == coreauth.ManualCooldownReason &&
					!existing.Quota.NextRecoverAt.IsZero() &&
					existing.Quota.NextRecoverAt.After(time.Now()) {
					return nil
				}
			}
			_, err := mgr.ClearCooldown(ctx, authID)
			return err
		}),
		// Auto-mark cooldown when wham reports limit_reached (including
		// the >=100% saturation case parseWhamUsage now flips to true).
		// Picks a deadline from the saturated window's reset_at — wham
		// returns absolute timestamps, so the cooldown lasts exactly as
		// long as upstream says it should. Idempotent: if the auth
		// already has a cooldown covering this deadline, skip.
		quota.WithLimitReachedSetter(func(ctx context.Context, authID string, snap coreauth.QuotaSnapshot) error {
			now := time.Now()
			var deadline time.Time
			if snap.UsedPercentPrimary >= 100 && !snap.ResetAtPrimary.IsZero() && snap.ResetAtPrimary.After(now) {
				deadline = snap.ResetAtPrimary
			}
			if snap.UsedPercentSecondary >= 100 && !snap.ResetAtSecondary.IsZero() && snap.ResetAtSecondary.After(now) {
				if deadline.IsZero() || snap.ResetAtSecondary.After(deadline) {
					deadline = snap.ResetAtSecondary
				}
			}
			if deadline.IsZero() {
				// No reset_at info from wham — fall back to a short
				// holding window so the auth comes back in time for
				// operator review without locking indefinitely.
				deadline = now.Add(15 * time.Minute)
			}
			if existing, ok := mgr.GetByID(authID); ok && existing != nil {
				if existing.Quota.Exceeded && !existing.Quota.NextRecoverAt.Before(deadline) {
					// Already covered by an equal-or-longer cooldown.
					return nil
				}
			}
			_, err := mgr.ForceCooldown(ctx, authID, deadline, "wham quota limit reached")
			if err == nil {
				log.Infof("quota-refresher: marked cooldown from wham | auth=%s primary_used=%d%% secondary_used=%d%% until=%s",
					authID, snap.UsedPercentPrimary, snap.UsedPercentSecondary, deadline.Format(time.RFC3339))
			}
			return err
		}),
		// Live plan_type from wham/usage. Agent-identity credentials freeze
		// plan at registration; without this a free→plus upgrade keeps the
		// free model catalog (no gpt-5.6-sol) until the operator re-imports
		// the file. Idempotent: same plan is a no-op.
		quota.WithPlanUpdater(func(ctx context.Context, auth *coreauth.Auth, planType string) error {
			return s.applyCodexPlanTypeFromUpstream(ctx, auth, planType)
		}),
		// Anchor floating quota windows: a fresh account that has never
		// made a real request reports reset_at ≈ fetched_at + 7d on every
		// wham/usage fetch (the window never starts counting, so its daily
		// allowance is wasted). Fire one minimal probe request to pin the
		// window and stop reset_at from sliding. The probe shares the
		// fetcher's transport/token plumbing (per-auth proxy honoured).
		quota.WithProbePin(func(ctx context.Context, auth *coreauth.Auth) error {
			return s.quotaFetcher.ProbePin(ctx, auth)
		}),
	)
	refresher.Start(ctx)
	s.quotaRefresher = refresher
	log.Infof("quota refresher started (interval=%s, concurrency=%d)", quota.DefaultRefreshInterval, quota.DefaultConcurrency)

	// Grok billing poller: display-only monthly-usage snapshots for xai auths.
	// Independent of the codex selector so it can never affect selection.
	if s.xaiBilling != nil {
		s.xaiBilling.Stop()
		s.xaiBilling = nil
	}
	xaiPoller := quota.NewXAIBillingPoller(func() []*coreauth.Auth { return mgr.List() }, quota.DefaultRefreshInterval)
	// Same history mirroring as the codex refresher, so grok rows get a curve too.
	if s.server != nil {
		xaiPoller.SetObserver(func(authID string, snap coreauth.QuotaSnapshot) {
			s.server.RecordQuotaSample(authID, snap.UsedPercentPrimary, snap.UsedPercentSecondary, snap.LimitReached, snap.ResetAtPrimary)
		})
	}
	xaiPoller.Start(ctx)
	s.xaiBilling = xaiPoller

	// Expose the snapshot + synchronous refresh to the management API so
	// the operator UI can render quota state next to each credential and
	// drive a per-account "refresh now" button. The wiring goes through
	// the api.Server because the management handler lives there; this
	// service holds the actual quota subsystem.
	if s.server != nil {
		// optTime is the same omit-zero helper the cooldown endpoint uses:
		// Go's omitempty leaves zero time.Time as "0001-01-01T00:00:00Z"
		// in JSON because time.Time is a struct, not a primitive. The
		// pointer pattern makes the field genuinely optional and the UI
		// can then test for null instead of parsing the absurd zero
		// timestamp and rendering "739768d ago".
		optTime := func(t time.Time) *time.Time {
			if t.IsZero() {
				return nil
			}
			return &t
		}
		toManagement := func(snap coreauth.QuotaSnapshot) managementHandlers.QuotaSnapshotData {
			return managementHandlers.QuotaSnapshotData{
				UsedPercentPrimary:   snap.UsedPercentPrimary,
				UsedPercentSecondary: snap.UsedPercentSecondary,
				LimitReached:         snap.LimitReached,
				ResetAtPrimary:       optTime(snap.ResetAtPrimary),
				ResetAtSecondary:     optTime(snap.ResetAtSecondary),
				FetchedAt:            optTime(snap.FetchedAt),
				PlanType:             strings.TrimSpace(snap.PlanType),
			}
		}
		snapshotFn := func(authID string) (managementHandlers.QuotaSnapshotData, bool) {
			// Overlay the codex refresher's dead-account marker (if any) onto
			// whatever quota snapshot we have. A permanently-dead credential
			// (e.g. wham/usage 402 deactivated_workspace) may carry a stale
			// snapshot or none at all; in the latter case we still return the
			// marker alone so the monitor can badge it for cleanup. xai auths
			// never carry a dead marker (it comes from the wham refresher).
			deadReason, deadSince, dead := "", time.Time{}, false
			if refresher != nil {
				deadReason, deadSince, dead = refresher.DeadMarker(authID)
			}
			attachDead := func(d managementHandlers.QuotaSnapshotData) managementHandlers.QuotaSnapshotData {
				if dead {
					d.DeadReason = deadReason
					d.DeadSince = optTime(deadSince)
				}
				return d
			}
			if snap, ok := selector.Snapshot(authID); ok {
				return attachDead(toManagement(snap)), true
			}
			// Fall back to the grok billing cache for xai auths, which the
			// codex selector never has a snapshot for.
			if xaiPoller != nil {
				if snap, ok := xaiPoller.Snapshot(authID); ok {
					return attachDead(toManagement(snap)), true
				}
			}
			// No quota snapshot, but the account is flagged dead — surface the
			// marker so the monitor renders the badge on a cold page load.
			if dead {
				return attachDead(managementHandlers.QuotaSnapshotData{}), true
			}
			return managementHandlers.QuotaSnapshotData{}, false
		}
		refreshFn := func(ctx context.Context, authID string) (managementHandlers.QuotaSnapshotData, bool, error) {
			// Route "refresh now" by provider: xai auths go to the billing
			// poller, everything else to the codex wham refresher.
			if existing, ok := mgr.GetByID(authID); ok && existing != nil &&
				strings.EqualFold(strings.TrimSpace(existing.Provider), "xai") {
				if xaiPoller == nil {
					return managementHandlers.QuotaSnapshotData{}, false, nil
				}
				snap, ok, err := xaiPoller.RefreshNow(ctx, authID)
				if err != nil || !ok {
					return managementHandlers.QuotaSnapshotData{}, ok, err
				}
				return toManagement(snap), true, nil
			}
			snap, ok, err := refresher.RefreshNow(ctx, authID)
			if err != nil || !ok {
				return managementHandlers.QuotaSnapshotData{}, ok, err
			}
			return toManagement(snap), true, nil
		}
		s.server.SetQuotaProviders(snapshotFn, refreshFn)
		// Forward request-body-bytes from the in-flight monitor into
		// the quota selector's local accumulator. The monitor invokes
		// this exactly once per request (at SetAuth time) so the next
		// CombinedQuotaScore reflects in-flight volume that wham/usage
		// has not yet absorbed — closing the ~10-min reporting gap
		// between wham snapshots.
		qsel := s.quotaSelector
		s.server.SetMonitorBytesRecorder(func(authID string, bytes int64) {
			qsel.RecordRequestBytes(authID, bytes)
		})
	}
}

// stopQuotaRefresher stops the background refresher if running. Idempotent.
func (s *Service) stopQuotaRefresher() {
	if s == nil {
		return
	}
	if s.xaiBilling != nil {
		s.xaiBilling.Stop()
		s.xaiBilling = nil
	}
	if s.quotaRefresher == nil {
		return
	}
	s.quotaRefresher.Stop()
	s.quotaRefresher = nil
}

// applyCodexPlanTypeFromUpstream rewrites a codex auth's stored plan_type from
// a live wham/usage response and re-registers the model catalog when the plan
// actually changes. Idempotent: same plan is a no-op. Used by the quota
// refresher (periodic + manual refresh) so agent-identity free→plus upgrades
// take effect without re-importing the credential file.
func (s *Service) applyCodexPlanTypeFromUpstream(ctx context.Context, auth *coreauth.Auth, planType string) error {
	if s == nil || s.coreManager == nil || auth == nil {
		return nil
	}
	planType = strings.TrimSpace(planType)
	if planType == "" {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return nil
	}
	current := ""
	if auth.Attributes != nil {
		current = strings.TrimSpace(auth.Attributes["plan_type"])
	}
	if current == "" && auth.Metadata != nil {
		if v, ok := auth.Metadata["plan_type"].(string); ok {
			current = strings.TrimSpace(v)
		}
	}
	if strings.EqualFold(current, planType) {
		return nil
	}

	// Work on a fresh clone from the manager so we don't race concurrent
	// updates against a stale refresher snapshot.
	live, ok := s.coreManager.GetByID(auth.ID)
	if !ok || live == nil {
		return fmt.Errorf("auth %q not found", auth.ID)
	}
	updated := live.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	if updated.Attributes == nil {
		updated.Attributes = make(map[string]string)
	}
	updated.Metadata["plan_type"] = planType
	updated.Attributes["plan_type"] = planType
	updated.UpdatedAt = time.Now()

	if _, err := s.coreManager.Update(ctx, updated); err != nil {
		return err
	}
	// Re-register the codex model catalog for the new plan (free omits
	// gpt-5.6-sol; plus/team/pro include it). RegisterClient also clears
	// learned model_not_supported flags for models now in the catalog.
	s.registerModelsForAuth(ctx, updated)
	s.coreManager.RefreshSchedulerEntry(updated.ID)
	log.Infof("quota-refresher: plan_type updated from wham | auth=%s %s -> %s", updated.ID, current, planType)
	return nil
}

func (s *Service) applyRetryConfig(cfg *config.Config) {
	if s == nil || s.coreManager == nil || cfg == nil {
		return
	}
	maxInterval := time.Duration(cfg.MaxRetryInterval) * time.Second
	s.coreManager.SetRetryConfig(cfg.RequestRetry, maxInterval, cfg.MaxRetryCredentials)
}

func openAICompatInfoFromAuth(a *coreauth.Auth) (providerKey string, compatName string, ok bool) {
	if a == nil {
		return "", "", false
	}
	if len(a.Attributes) > 0 {
		providerKey = strings.TrimSpace(a.Attributes["provider_key"])
		compatName = strings.TrimSpace(a.Attributes["compat_name"])
		if compatName != "" {
			if providerKey == "" {
				providerKey = compatName
			}
			return strings.ToLower(providerKey), compatName, true
		}
	}
	if strings.EqualFold(strings.TrimSpace(a.Provider), "openai-compatibility") {
		return "openai-compatibility", strings.TrimSpace(a.Label), true
	}
	return "", "", false
}

func (s *Service) hasNativeOpenAICompatExecutorConfig(a *coreauth.Auth, providerKey string) bool {
	if a == nil {
		return false
	}
	providerKey = strings.ToLower(strings.TrimSpace(providerKey))
	if a.Attributes != nil {
		if strings.TrimSpace(a.Attributes["base_url"]) != "" {
			return true
		}
		if strings.TrimSpace(a.Attributes["compat_name"]) != "" {
			return true
		}
	}
	if strings.EqualFold(strings.TrimSpace(a.Provider), "openai-compatibility") {
		return true
	}
	if s == nil || s.cfg == nil {
		return false
	}

	candidates := make([]string, 0, 3)
	if providerKey != "" {
		candidates = append(candidates, providerKey)
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["provider_key"]); v != "" {
			candidates = append(candidates, strings.ToLower(v))
		}
	}
	if provider := strings.TrimSpace(a.Provider); provider != "" {
		candidates = append(candidates, strings.ToLower(provider))
	}

	for i := range s.cfg.OpenAICompatibility {
		compat := &s.cfg.OpenAICompatibility[i]
		if compat.Disabled {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(compat.Name))
		if name == "" {
			continue
		}
		for _, candidate := range candidates {
			if candidate != "" && candidate == name {
				return true
			}
		}
	}
	return false
}

func (s *Service) ensureExecutorsForAuth(a *coreauth.Auth) {
	s.ensureExecutorsForAuthWithMode(a, false)
}

func (s *Service) ensureExecutorsForAuthWithMode(a *coreauth.Auth, forceReplace bool) {
	if a == nil {
		return
	}
	s.registerAvailableExecutors(context.Background(), executorRegistrationOptions{
		auths:             []*coreauth.Auth{a},
		forceReplaceAuths: forceReplace,
	})
}

func (s *Service) registerAvailableExecutors(ctx context.Context, opts executorRegistrationOptions) {
	if s == nil || s.coreManager == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	// Keep all Service-owned executor registration paths here so native, Home,
	// auth-derived, and plugin executors stay in the same binding order.
	if opts.includeBaseline {
		s.registerExecutorsForAuths(baselineExecutorAuths(), true)
	}
	if len(opts.auths) > 0 {
		s.registerExecutorsForAuths(opts.auths, opts.forceReplaceAuths)
	}
	if opts.includePlugins && s.pluginHost != nil {
		registerPluginExecutors(s.pluginHost, s.coreManager)
	}
}

func baselineExecutorAuths() []*coreauth.Auth {
	providers := []string{
		"codex",
		"claude",
		"gemini",
		"vertex",
		"gemini-cli",
		"aistudio",
		"antigravity",
		"kimi",
		"xai",
		"openai-compatibility",
	}
	auths := make([]*coreauth.Auth, 0, len(providers))
	for _, provider := range providers {
		auth := &coreauth.Auth{
			ID:       provider,
			Provider: provider,
		}
		if provider == "openai-compatibility" {
			auth.Attributes = map[string]string{"compat_name": "openai-compatibility"}
		}
		auths = append(auths, auth)
	}
	return auths
}

func (s *Service) registerExecutorsForAuths(auths []*coreauth.Auth, forceReplace bool) {
	reboundCodex := false
	for _, auth := range auths {
		if auth != nil && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			if reboundCodex && forceReplace {
				continue
			}
			reboundCodex = true
		}
		s.registerExecutorForAuth(auth, forceReplace)
	}
}

func (s *Service) registerExecutorForAuth(a *coreauth.Auth, forceReplace bool) {
	if s == nil || s.coreManager == nil || a == nil {
		return
	}
	if strings.EqualFold(strings.TrimSpace(a.Provider), "codex") {
		if !forceReplace {
			existingExecutor, hasExecutor := s.coreManager.Executor("codex")
			if hasExecutor {
				_, isCodexAutoExecutor := existingExecutor.(*executor.CodexAutoExecutor)
				if isCodexAutoExecutor {
					return
				}
			}
		}
		s.coreManager.RegisterExecutor(executor.NewCodexAutoExecutor(s.cfg))
		return
	}
	// Skip disabled auth entries when (re)binding executors.
	// Disabled auths can linger during config reloads (e.g., removed OpenAI-compat entries)
	// and must not override active provider executors.
	if a.Disabled {
		return
	}
	if compatProviderKey, _, isCompat := openAICompatInfoFromAuth(a); isCompat {
		if compatProviderKey == "" {
			compatProviderKey = strings.ToLower(strings.TrimSpace(a.Provider))
		}
		if compatProviderKey == "" {
			compatProviderKey = "openai-compatibility"
		}
		s.coreManager.RegisterExecutor(executor.NewOpenAICompatExecutor(compatProviderKey, s.cfg))
		return
	}
	switch strings.ToLower(a.Provider) {
	case "gemini":
		s.coreManager.RegisterExecutor(executor.NewGeminiExecutor(s.cfg))
	case "vertex":
		s.coreManager.RegisterExecutor(executor.NewGeminiVertexExecutor(s.cfg))
	case "gemini-cli":
		s.coreManager.RegisterExecutor(executor.NewGeminiCLIExecutor(s.cfg))
	case "aistudio":
		if s.wsGateway != nil {
			s.coreManager.RegisterExecutor(executor.NewAIStudioExecutor(s.cfg, a.ID, s.wsGateway))
		}
		return
	case "antigravity":
		s.coreManager.RegisterExecutor(executor.NewAntigravityExecutor(s.cfg))
	case "claude":
		s.coreManager.RegisterExecutor(executor.NewClaudeExecutor(s.cfg))
	case "kimi":
		s.coreManager.RegisterExecutor(executor.NewKimiExecutor(s.cfg))
	case "xai":
		s.coreManager.RegisterExecutor(executor.NewXAIExecutor(s.cfg))
	default:
		providerKey := strings.ToLower(strings.TrimSpace(a.Provider))
		if providerKey == "" {
			providerKey = "openai-compatibility"
		}
		if s.pluginHost != nil &&
			s.pluginHost.HasExecutorCandidateProvider(providerKey) &&
			!s.hasNativeOpenAICompatExecutorConfig(a, providerKey) {
			return
		}
		s.coreManager.RegisterExecutor(executor.NewOpenAICompatExecutor(providerKey, s.cfg))
	}
}

func (s *Service) registerResolvedModelsForAuth(a *coreauth.Auth, providerKey string, models []*ModelInfo) {
	if a == nil || a.ID == "" {
		return
	}
	providerKey = strings.ToLower(strings.TrimSpace(providerKey))
	if providerKey == "" {
		GlobalModelRegistry().UnregisterClient(a.ID)
		return
	}
	normalizedModels := make([]*ModelInfo, 0, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelID := strings.TrimSpace(model.ID)
		if modelID == "" {
			continue
		}
		clone := *model
		clone.ID = modelID
		normalizedModels = append(normalizedModels, &clone)
	}
	if len(normalizedModels) == 0 {
		GlobalModelRegistry().UnregisterClient(a.ID)
		return
	}
	GlobalModelRegistry().RegisterClient(a.ID, providerKey, normalizedModels)
}

func (s *Service) pluginModelsForProvider(providerKey string) []*ModelInfo {
	if s == nil || s.pluginHost == nil {
		return nil
	}
	return s.pluginHost.ModelsForProvider(providerKey)
}

func (s *Service) appendPluginModels(providerKey string, models []*ModelInfo) []*ModelInfo {
	pluginModels := s.pluginModelsForProvider(providerKey)
	if len(pluginModels) == 0 {
		return models
	}
	out := make([]*ModelInfo, 0, len(models)+len(pluginModels))
	seen := make(map[string]struct{}, len(models)+len(pluginModels))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelID := strings.TrimSpace(model.ID)
		if modelID != "" {
			seen[modelID] = struct{}{}
		}
		out = append(out, model)
	}
	for _, model := range pluginModels {
		if model == nil {
			continue
		}
		modelID := strings.TrimSpace(model.ID)
		if modelID == "" {
			continue
		}
		if _, exists := seen[modelID]; exists {
			continue
		}
		seen[modelID] = struct{}{}
		out = append(out, model)
	}
	return out
}

func (s *Service) tryRegisterPluginModelsForAuth(ctx context.Context, a *coreauth.Auth, provider, authKind string, excluded []string) bool {
	if s == nil || s.pluginHost == nil || a == nil {
		return false
	}
	result := s.pluginHost.ModelsForAuth(ctx, a)
	if !result.Handled {
		return false
	}
	if result.Err != nil {
		return true
	}
	activeAuth := a
	providerKey := strings.ToLower(strings.TrimSpace(result.Provider))
	if providerKey == "" {
		providerKey = strings.ToLower(strings.TrimSpace(provider))
	}
	if result.Auth != nil && s.coreManager != nil {
		result.Auth.ID = a.ID
		if result.Auth.Provider == "" {
			result.Auth.Provider = a.Provider
		}
		if result.Auth.FileName == "" {
			result.Auth.FileName = a.FileName
		}
		if result.Auth.Attributes == nil {
			result.Auth.Attributes = make(map[string]string)
		}
		for key, value := range a.Attributes {
			if _, exists := result.Auth.Attributes[key]; !exists {
				result.Auth.Attributes[key] = value
			}
		}
		if updated, errUpdate := s.coreManager.Update(context.Background(), result.Auth); errUpdate == nil && updated != nil {
			activeAuth = updated.Clone()
		}
	}
	if activeAuth == nil {
		activeAuth = a
	}
	if activeProvider := strings.ToLower(strings.TrimSpace(activeAuth.Provider)); activeProvider != "" {
		providerKey = activeProvider
	}
	if providerKey == "" {
		providerKey = strings.ToLower(strings.TrimSpace(provider))
	}
	activeAuthKind := strings.ToLower(strings.TrimSpace(activeAuth.Attributes["auth_kind"]))
	if activeAuthKind == "" {
		if kind, _ := activeAuth.AccountInfo(); strings.EqualFold(kind, "api_key") {
			activeAuthKind = "apikey"
		}
	}
	activeExcluded := s.oauthExcludedModels(providerKey, activeAuthKind)
	if a == activeAuth && len(activeExcluded) == 0 {
		activeExcluded = excluded
	}
	if activeAuth.Attributes != nil {
		if val, ok := activeAuth.Attributes["excluded_models"]; ok && strings.TrimSpace(val) != "" {
			activeExcluded = strings.Split(val, ",")
		}
	}
	models := applyExcludedModels(result.Models, activeExcluded)
	models = applyOAuthModelAlias(s.cfg, providerKey, activeAuthKind, models)
	if len(models) > 0 {
		s.registerResolvedModelsForAuth(activeAuth, providerKey, applyModelPrefixes(models, activeAuth.Prefix, s.cfg != nil && s.cfg.ForceModelPrefix))
		return true
	}
	GlobalModelRegistry().UnregisterClient(activeAuth.ID)
	return true
}

func (s *Service) applyConfigUpdate(newCfg *config.Config) {
	if s == nil {
		return
	}

	s.configUpdateMu.Lock()
	defer s.configUpdateMu.Unlock()

	previousStrategy := ""
	var previousSessionAffinity bool
	var previousSessionAffinityTTL string
	var previousSessionAffinityStrict bool
	s.cfgMu.RLock()
	if s.cfg != nil {
		previousStrategy = strings.ToLower(strings.TrimSpace(s.cfg.Routing.Strategy))
		previousSessionAffinity = s.cfg.Routing.SessionAffinity
		previousSessionAffinityTTL = s.cfg.Routing.SessionAffinityTTL
		previousSessionAffinityStrict = s.cfg.Routing.SessionAffinityStrict
	}
	s.cfgMu.RUnlock()

	if newCfg == nil {
		s.cfgMu.RLock()
		newCfg = s.cfg
		s.cfgMu.RUnlock()
	}
	if newCfg == nil {
		return
	}

	nextStrategy := strings.ToLower(strings.TrimSpace(newCfg.Routing.Strategy))
	normalizeStrategy := func(strategy string) string {
		switch strategy {
		case "fill-first", "fillfirst", "ff":
			return "fill-first"
		default:
			return "round-robin"
		}
	}
	previousStrategy = normalizeStrategy(previousStrategy)
	nextStrategy = normalizeStrategy(nextStrategy)

	nextSessionAffinity := newCfg.Routing.SessionAffinity
	nextSessionAffinityTTL := newCfg.Routing.SessionAffinityTTL
	nextSessionAffinityStrict := newCfg.Routing.SessionAffinityStrict

	selectorChanged := previousStrategy != nextStrategy ||
		previousSessionAffinity != nextSessionAffinity ||
		previousSessionAffinityTTL != nextSessionAffinityTTL ||
		previousSessionAffinityStrict != nextSessionAffinityStrict

	if s.coreManager != nil && selectorChanged {
		var selector coreauth.Selector
		var leastBound *coreauth.LeastBoundSelector
		switch nextStrategy {
		case "fill-first":
			selector = &coreauth.FillFirstSelector{}
		default:
			leastBound = coreauth.NewLeastBoundSelector(nil, nil)
			selector = leastBound
		}

		// Wrap with quota-aware selection. Mirrors the chain in builder.go
		// for the fresh-start path. Async mode keeps Pick latency bounded
		// to cache reads; the refresher is restarted below so it pushes
		// snapshots into the NEW selector instance.
		quotaFetcher := quota.NewCodexWhamFetcher()
		quotaSelector := coreauth.NewLeastRemainingQuotaSelector(coreauth.LeastRemainingQuotaConfig{
			Inner:   selector,
			Fetcher: quotaFetcher,
			Async:   true,
			// Mirror the builder's TTL choice — see the comment there
			// for the rationale (TTL must outlast the refresh interval
			// so async picks never fall back to neutral while the
			// refresher is between successful cycles).
			TTL: 2 * quota.DefaultRefreshInterval,
		})
		selector = quotaSelector
		s.quotaFetcher = quotaFetcher
		s.quotaSelector = quotaSelector

		if nextSessionAffinity {
			ttl := time.Hour
			if ttlStr := strings.TrimSpace(nextSessionAffinityTTL); ttlStr != "" {
				if parsed, err := time.ParseDuration(ttlStr); err == nil && parsed > 0 {
					ttl = parsed
				}
			}
			affinity := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
				Fallback:        selector,
				TTL:             ttl,
				PersistencePath: sessionAffinityCachePath(newCfg),
				Strict:          nextSessionAffinityStrict,
			})
			if leastBound != nil {
				qs := quotaSelector
				// Mirror builder.go: combined primary*100 + secondary
				// so weekly usage breaks primary-tied ties.
				leastBound.SetSecondaryScore(func(authID string) int {
					score, ok := qs.CombinedQuotaScore(authID)
					if !ok {
						return coreauth.DefaultNeutralUsedPercent * 100
					}
					return score
				})
			}
			selector = affinity
		}

		s.coreManager.SetSelector(selector)

		// Rebind the background quota refresher to the freshly constructed
		// selector + fetcher. Home mode runs without a refresher; if the
		// service did not have one already, do not start one now.
		if s.quotaRefresher != nil {
			s.startQuotaRefresher(context.Background())
		}
	}

	s.applyRetryConfig(newCfg)
	s.applyPprofConfig(newCfg)
	if s.server != nil {
		s.server.UpdateClients(newCfg)
	}
	s.cfgMu.Lock()
	s.cfg = newCfg
	s.cfgMu.Unlock()
	if s.coreManager != nil {
		s.coreManager.SetConfig(newCfg)
		s.coreManager.SetOAuthModelAlias(newCfg.OAuthModelAlias)
	}
	var auths []*coreauth.Auth
	if s.coreManager != nil {
		auths = s.coreManager.List()
	}
	s.registerAvailableExecutors(context.Background(), executorRegistrationOptions{
		includeBaseline:   newCfg.Home.Enabled,
		forceReplaceAuths: true,
		auths:             auths,
	})
	ctx := context.Background()
	s.registerConfigAPIKeyAuths(ctx, newCfg)
	s.syncPluginRuntime(ctx)
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

	tasks := make([]modelRegistrationTask, 0, len(auths))
	for _, auth := range auths {
		if !isConfigAPIKeyAuth(auth) {
			continue
		}
		prepared := s.prepareCoreAuthForModelRegistration(ctx, auth)
		if prepared == nil {
			continue
		}
		authForRegistration := prepared
		tasks = append(tasks, modelRegistrationTask{
			phase:    modelRegistrationPhaseConfigAPIKey,
			category: modelRegistrationCategory(authForRegistration),
			run: func() {
				s.completeModelRegistrationForAuth(ctx, authForRegistration)
			},
		})
	}
	s.runModelRegistrationTasks(ctx, tasks)
}

func forceHomeRuntimeConfig(cfg *config.Config) {
	if cfg == nil {
		return
	}
	cfg.APIKeys = nil
	cfg.UsageStatisticsEnabled = true
	cfg.DisableCooling = true
	cfg.WebsocketAuth = false
	cfg.EnableGeminiCLIEndpoint = false
	cfg.RemoteManagement.AllowRemote = false
	cfg.RemoteManagement.DisableControlPanel = true
}

func (s *Service) applyHomeOverlay(remoteCfg *config.Config) {
	if s == nil || remoteCfg == nil {
		return
	}

	s.cfgMu.RLock()
	baseCfg := s.cfg
	s.cfgMu.RUnlock()
	if baseCfg == nil {
		return
	}

	merged := *remoteCfg
	merged.Host = baseCfg.Host
	merged.Port = baseCfg.Port
	merged.TLS = baseCfg.TLS
	merged.Home = baseCfg.Home
	forceHomeRuntimeConfig(&merged)

	logHomeConfigChanges(baseCfg, &merged)
	s.applyConfigUpdate(&merged)
}

func logHomeConfigChanges(oldCfg, newCfg *config.Config) {
	if oldCfg == nil || newCfg == nil || !newCfg.Home.Enabled || (!oldCfg.Debug && !newCfg.Debug) {
		return
	}

	details := diff.BuildConfigChangeDetails(oldCfg, newCfg)
	if len(details) == 0 {
		return
	}

	if newCfg.Debug && !log.IsLevelEnabled(log.DebugLevel) {
		util.SetLogLevel(newCfg)
	}

	log.Debugf("home config changes detected:")
	for _, detail := range details {
		log.Debugf("  %s", detail)
	}
}

func (s *Service) startHomeUsageForwarder(ctx context.Context, client *home.Client) {
	if s == nil || client == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	sleep := func(d time.Duration) bool {
		if d <= 0 {
			return true
		}
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if !client.HeartbeatOK() {
				if !sleep(time.Second) {
					return
				}
				continue
			}

			items := redisqueue.PopOldest(64)
			if len(items) == 0 {
				if !sleep(500 * time.Millisecond) {
					return
				}
				continue
			}

			for i := range items {
				if errPush := client.LPushUsage(ctx, items[i]); errPush != nil {
					for j := i; j < len(items); j++ {
						redisqueue.Enqueue(items[j])
					}
					if !sleep(time.Second) {
						return
					}
					break
				}
			}
		}
	}()
}

func (s *Service) startHomeSubscriber(ctx context.Context) {
	if s == nil {
		return
	}
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	if cfg == nil || !cfg.Home.Enabled {
		return
	}

	if s.homeCancel != nil {
		s.homeCancel()
		s.homeCancel = nil
	}
	if s.homeClient != nil {
		s.homeClient.Close()
		s.homeClient = nil
	}
	if s.homeLogForwarder != nil {
		s.homeLogForwarder.Stop()
		s.homeLogForwarder = nil
	}

	homeCtx := ctx
	if homeCtx == nil {
		homeCtx = context.Background()
	}
	homeCtx, cancel := context.WithCancel(homeCtx)
	s.homeCancel = cancel

	client := home.New(cfg.Home)
	s.homeClient = client
	home.SetCurrent(client)

	go client.StartConfigSubscriber(homeCtx, func(raw []byte) error {
		parsed, err := config.ParseConfigBytes(raw)
		if err != nil {
			log.Warnf("failed to parse home config payload: %v", err)
			return err
		}
		s.applyHomeOverlay(parsed)
		return nil
	})
	s.startHomeUsageForwarder(homeCtx, client)
	s.homeLogForwarder = logging.StartHomeAppLogForwarder(0)
}

// Run starts the service and blocks until the context is cancelled or the server stops.
// It initializes all components including authentication, file watching, HTTP server,
// and starts processing requests. The method blocks until the context is cancelled.
//
// Parameters:
//   - ctx: The context for controlling the service lifecycle
//
// Returns:
//   - error: An error if the service fails to start or run
func (s *Service) Run(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("cliproxy: service is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	usage.StartDefault(ctx)
	homeEnabled := s.cfg != nil && s.cfg.Home.Enabled
	if homeEnabled {
		forceHomeRuntimeConfig(s.cfg)
		redisqueue.SetUsageStatisticsEnabled(true)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	defer func() {
		if err := s.Shutdown(shutdownCtx); err != nil {
			log.Errorf("service shutdown returned error: %v", err)
		}
	}()

	if !homeEnabled {
		if errEnsureAuthDir := s.ensureAuthDir(); errEnsureAuthDir != nil {
			return errEnsureAuthDir
		}
	}

	s.applyRetryConfig(s.cfg)

	s.registerPluginAuthParser()
	if s.coreManager != nil && !homeEnabled {
		if errLoad := s.coreManager.Load(ctx); errLoad != nil {
			log.Warnf("failed to load auth store: %v", errLoad)
		}
	}

	if !homeEnabled {
		tokenResult, err := s.tokenProvider.Load(ctx, s.cfg)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		if tokenResult == nil {
			tokenResult = &TokenClientResult{}
		}

		apiKeyResult, err := s.apiKeyProvider.Load(ctx, s.cfg)
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		if apiKeyResult == nil {
			apiKeyResult = &APIKeyClientResult{}
		}
	}

	// legacy clients removed; no caches to refresh

	s.ensureWebsocketGateway()
	if homeEnabled {
		s.registerAvailableExecutors(ctx, executorRegistrationOptions{
			includeBaseline: true,
		})
		// Home mode does not expose in-process Redis RESP usage output; usage is forwarded to home instead.
		redisqueue.SetEnabled(true)
	}

	// handlers no longer depend on legacy clients; pass nil slice initially
	s.server = api.NewServer(s.cfg, s.coreManager, s.accessManager, s.configPath, s.serverOptions...)
	s.syncPluginRuntimeConfig(ctx)
	if homeEnabled {
		s.syncPluginModelRuntime(ctx)
	}

	if s.authManager == nil {
		s.authManager = newDefaultAuthManager()
	}

	if homeEnabled {
		s.startHomeSubscriber(ctx)
	}

	if s.server != nil && s.wsGateway != nil {
		s.server.AttachWebsocketRoute(s.wsGateway.Path(), s.wsGateway.Handler())
		s.server.SetWebsocketAuthChangeHandler(func(oldEnabled, newEnabled bool) {
			if oldEnabled == newEnabled {
				return
			}
			if !oldEnabled && newEnabled {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if errStop := s.wsGateway.Stop(ctx); errStop != nil {
					log.Warnf("failed to reset websocket connections after ws-auth change %t -> %t: %v", oldEnabled, newEnabled, errStop)
					return
				}
				log.Debugf("ws-auth enabled; existing websocket sessions terminated to enforce authentication")
				return
			}
			log.Debugf("ws-auth disabled; existing websocket sessions remain connected")
		})
	}

	if s.hooks.OnBeforeStart != nil {
		s.hooks.OnBeforeStart(s.cfg)
	}

	s.serverErr = make(chan error, 1)
	go func() {
		if errStart := s.server.Start(); errStart != nil {
			s.serverErr <- errStart
		} else {
			s.serverErr <- nil
		}
	}()

	// Race the server's startup against a short delay. net.Listen
	// returns its bind error synchronously, so 100ms is plenty for the
	// goroutine above to report a bind failure before we proceed to
	// start the watcher / refreshers — all of which write to auth files
	// and would thrash them across competing instances if the listener
	// never bound. Without this guard, the "started successfully"
	// message below would print even when the bind failed, then setup
	// would continue, OAuth refresh would rotate tokens behind the back
	// of the real owner of the port, and every restart cycle would
	// invalidate live credentials silently.
	select {
	case errServer := <-s.serverErr:
		if errServer != nil {
			log.Errorf("API server failed to start on %s:%d: %v", s.cfg.Host, s.cfg.Port, errServer)
			return errServer
		}
		log.Warnf("API server returned nil during startup window — treating as early shutdown")
		return nil
	case <-time.After(100 * time.Millisecond):
		fmt.Printf("API server started successfully on: %s:%d\n", s.cfg.Host, s.cfg.Port)
	}

	s.applyPprofConfig(s.cfg)

	if s.hooks.OnAfterStart != nil {
		s.hooks.OnAfterStart(s)
	}

	if !homeEnabled {
		var watcherWrapper *WatcherWrapper
		reloadCallback := func(newCfg *config.Config) { s.applyConfigUpdate(newCfg) }

		watcherWrapper, errCreate := s.watcherFactory(s.configPath, s.cfg.AuthDir, reloadCallback)
		if errCreate != nil {
			return fmt.Errorf("cliproxy: failed to create watcher: %w", errCreate)
		}
		s.watcher = watcherWrapper
		s.ensureAuthUpdateQueue(ctx)
		if s.authUpdates != nil {
			watcherWrapper.SetAuthUpdateQueue(s.authUpdates)
		}
		watcherWrapper.SetConfig(s.cfg)
		s.registerPluginAuthParser()

		watcherCtx, watcherCancel := context.WithCancel(context.Background())
		s.watcherCancel = watcherCancel
		if errStart := watcherWrapper.Start(watcherCtx); errStart != nil {
			return fmt.Errorf("cliproxy: failed to start watcher: %w", errStart)
		}
		log.Info("file watcher started for config and auth directory changes")
		s.syncPluginModelRuntime(ctx)
	}

	s.registerModelRefreshCallback()

	// Prefer core auth manager auto refresh if available.
	if s.coreManager != nil && !homeEnabled {
		interval := 15 * time.Minute
		s.coreManager.StartAutoRefresh(context.Background(), interval)
		log.Infof("core auth auto-refresh started (interval=%s)", interval)
	}

	// Quota refresher starts after auth load so the very first cycle
	// already sees the persisted credential list. Home mode is excluded —
	// home pushes auth bundles from a remote source on its own schedule
	// and runs its own selector chain.
	if !homeEnabled {
		s.startQuotaRefresher(context.Background())
	}

	select {
	case <-ctx.Done():
		log.Debug("service context cancelled, shutting down...")
		return ctx.Err()
	case errServer := <-s.serverErr:
		return errServer
	}
}

// Shutdown gracefully stops background workers and the HTTP server.
// It ensures all resources are properly cleaned up and connections are closed.
// The shutdown is idempotent and can be called multiple times safely.
//
// Parameters:
//   - ctx: The context for controlling the shutdown timeout
//
// Returns:
//   - error: An error if shutdown fails
func (s *Service) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	var shutdownErr error
	s.shutdownOnce.Do(func() {
		if ctx == nil {
			ctx = context.Background()
		}

		if s.homeCancel != nil {
			s.homeCancel()
			s.homeCancel = nil
		}
		if s.homeClient != nil {
			s.homeClient.Close()
			s.homeClient = nil
		}
		if s.homeLogForwarder != nil {
			s.homeLogForwarder.Stop()
			s.homeLogForwarder = nil
		}
		home.ClearCurrent()

		// legacy refresh loop removed; only stopping core auth manager below

		if s.watcherCancel != nil {
			s.watcherCancel()
		}
		s.stopQuotaRefresher()
		if s.coreManager != nil {
			s.coreManager.StopAutoRefresh()
		}
		if s.watcher != nil {
			if err := s.watcher.Stop(); err != nil {
				log.Errorf("failed to stop file watcher: %v", err)
				shutdownErr = err
			}
		}
		if s.wsGateway != nil {
			if err := s.wsGateway.Stop(ctx); err != nil {
				log.Errorf("failed to stop websocket gateway: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}
		if s.authQueueStop != nil {
			s.authQueueStop()
			s.authQueueStop = nil
		}

		if errShutdownPprof := s.shutdownPprof(ctx); errShutdownPprof != nil {
			log.Errorf("failed to stop pprof server: %v", errShutdownPprof)
			if shutdownErr == nil {
				shutdownErr = errShutdownPprof
			}
		}

		// no legacy clients to persist

		if s.server != nil {
			shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()
			if err := s.server.Stop(shutdownCtx); err != nil {
				log.Errorf("error stopping API server: %v", err)
				if shutdownErr == nil {
					shutdownErr = err
				}
			}
		}

		if s.pluginHost != nil {
			sdktranslator.SetPluginHooks(nil)
			sdkAuth.RegisterPluginAuthParser(nil)
			if s.watcher != nil {
				s.watcher.SetPluginAuthParser(nil)
			}
			s.pluginHost.ApplyConfig(ctx, &config.Config{})
			s.pluginHost.RegisterModels(ctx, registry.GetGlobalRegistry())
			s.registerAvailableExecutors(ctx, executorRegistrationOptions{
				includePlugins: true,
			})
			s.pluginHost.RegisterFrontendAuthProviders()
			s.pluginHost.ShutdownAll()
			if s.accessManager != nil {
				s.accessManager.SetProviders(sdkaccess.RegisteredProviders())
			}
		}

		usage.StopDefault()
	})
	return shutdownErr
}

func (s *Service) ensureAuthDir() error {
	info, err := os.Stat(s.cfg.AuthDir)
	if err != nil {
		if os.IsNotExist(err) {
			if mkErr := os.MkdirAll(s.cfg.AuthDir, 0o755); mkErr != nil {
				return fmt.Errorf("cliproxy: failed to create auth directory %s: %w", s.cfg.AuthDir, mkErr)
			}
			log.Infof("created missing auth directory: %s", s.cfg.AuthDir)
			return nil
		}
		return fmt.Errorf("cliproxy: error checking auth directory %s: %w", s.cfg.AuthDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("cliproxy: auth path exists but is not a directory: %s", s.cfg.AuthDir)
	}
	return nil
}

// registerModelsForAuth (re)binds provider models in the global registry using the core auth ID as client identifier.
func (s *Service) registerModelsForAuth(ctx context.Context, a *coreauth.Auth) {
	if a == nil || a.ID == "" {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if a.Disabled {
		GlobalModelRegistry().UnregisterClient(a.ID)
		return
	}
	authKind := strings.ToLower(strings.TrimSpace(a.Attributes["auth_kind"]))
	if authKind == "" {
		if kind, _ := a.AccountInfo(); strings.EqualFold(kind, "api_key") {
			authKind = "apikey"
		}
	}
	if a.Attributes != nil {
		if v := strings.TrimSpace(a.Attributes["gemini_virtual_primary"]); strings.EqualFold(v, "true") {
			GlobalModelRegistry().UnregisterClient(a.ID)
			return
		}
	}
	// Unregister legacy client ID (if present) to avoid double counting
	if a.Runtime != nil {
		if idGetter, ok := a.Runtime.(interface{ GetClientID() string }); ok {
			if rid := idGetter.GetClientID(); rid != "" && rid != a.ID {
				GlobalModelRegistry().UnregisterClient(rid)
			}
		}
	}
	provider := strings.ToLower(strings.TrimSpace(a.Provider))
	compatProviderKey, compatDisplayName, compatDetected := openAICompatInfoFromAuth(a)
	if compatDetected {
		provider = "openai-compatibility"
	}
	excluded := s.oauthExcludedModels(provider, authKind)
	// The synthesizer pre-merges per-account and global exclusions into the "excluded_models" attribute.
	// If this attribute is present, it represents the complete list of exclusions and overrides the global config.
	if a.Attributes != nil {
		if val, ok := a.Attributes["excluded_models"]; ok && strings.TrimSpace(val) != "" {
			excluded = strings.Split(val, ",")
		}
	}
	if s.tryRegisterPluginModelsForAuth(ctx, a, provider, authKind, excluded) {
		return
	}
	var models []*ModelInfo
	switch provider {
	case "gemini":
		models = registry.GetGeminiModels()
		if entry := s.resolveConfigGeminiKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildGeminiConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "vertex":
		// Vertex AI Gemini supports the same model identifiers as Gemini.
		models = registry.GetGeminiVertexModels()
		if entry := s.resolveConfigVertexCompatKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildVertexCompatConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "gemini-cli":
		models = registry.GetGeminiCLIModels()
		models = applyExcludedModels(models, excluded)
	case "aistudio":
		models = registry.GetAIStudioModels()
		models = applyExcludedModels(models, excluded)
	case "antigravity":
		models = registry.GetAntigravityModels()
		models = applyAntigravityFetchedModelCapabilities(models, s.fetchAntigravityModelCapabilityHintsForAuth(ctx, a))
		models = applyExcludedModels(models, excluded)
	case "claude":
		models = registry.GetClaudeModels()
		if entry := s.resolveConfigClaudeKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildClaudeConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "codex":
		codexPlanType := ""
		if a.Attributes != nil {
			codexPlanType = strings.TrimSpace(a.Attributes["plan_type"])
		}
		switch strings.ToLower(codexPlanType) {
		case "pro":
			models = registry.GetCodexProModels()
		case "plus":
			models = registry.GetCodexPlusModels()
		case "team", "business", "go":
			models = registry.GetCodexTeamModels()
		case "free":
			models = registry.GetCodexFreeModels()
		default:
			models = registry.GetCodexProModels()
		}
		if entry := s.resolveConfigCodexKey(a); entry != nil {
			if len(entry.Models) > 0 {
				models = buildCodexConfigModels(entry)
			}
			if authKind == "apikey" {
				excluded = entry.ExcludedModels
			}
		}
		models = applyExcludedModels(models, excluded)
	case "kimi":
		models = registry.GetKimiModels()
		models = applyExcludedModels(models, excluded)
	case "xai":
		models = registry.GetXAIModels()
		models = applyExcludedModels(models, excluded)
	default:
		// Handle OpenAI-compatibility providers by name using config
		if s.cfg != nil {
			providerKey := provider
			compatName := strings.TrimSpace(a.Provider)
			isCompatAuth := false
			if compatDetected {
				if compatProviderKey != "" {
					providerKey = compatProviderKey
				}
				if compatDisplayName != "" {
					compatName = compatDisplayName
				}
				isCompatAuth = true
			}
			if strings.EqualFold(providerKey, "openai-compatibility") {
				isCompatAuth = true
				if a.Attributes != nil {
					if v := strings.TrimSpace(a.Attributes["compat_name"]); v != "" {
						compatName = v
					}
					if v := strings.TrimSpace(a.Attributes["provider_key"]); v != "" {
						providerKey = strings.ToLower(v)
						isCompatAuth = true
					}
				}
				if providerKey == "openai-compatibility" && compatName != "" {
					providerKey = strings.ToLower(compatName)
				}
			} else if a.Attributes != nil {
				if v := strings.TrimSpace(a.Attributes["compat_name"]); v != "" {
					compatName = v
					isCompatAuth = true
				}
				if v := strings.TrimSpace(a.Attributes["provider_key"]); v != "" {
					providerKey = strings.ToLower(v)
					isCompatAuth = true
				}
			}
			for i := range s.cfg.OpenAICompatibility {
				compat := &s.cfg.OpenAICompatibility[i]
				if compat.Disabled {
					continue
				}
				if strings.EqualFold(compat.Name, compatName) {
					isCompatAuth = true
					ms := buildOpenAICompatibilityConfigModels(compat)
					// Register and return
					if len(ms) > 0 {
						if providerKey == "" {
							providerKey = "openai-compatibility"
						}
						ms = s.appendPluginModels(providerKey, ms)
						s.registerResolvedModelsForAuth(a, providerKey, applyModelPrefixes(ms, a.Prefix, s.cfg.ForceModelPrefix))
					} else {
						// Ensure stale registrations are cleared when model list becomes empty.
						ms = s.appendPluginModels(providerKey, nil)
						if len(ms) > 0 {
							s.registerResolvedModelsForAuth(a, providerKey, applyModelPrefixes(ms, a.Prefix, s.cfg.ForceModelPrefix))
						} else {
							GlobalModelRegistry().UnregisterClient(a.ID)
						}
					}
					return
				}
			}
			if isCompatAuth {
				models = s.appendPluginModels(providerKey, nil)
				if len(models) > 0 {
					s.registerResolvedModelsForAuth(a, providerKey, applyModelPrefixes(models, a.Prefix, s.cfg != nil && s.cfg.ForceModelPrefix))
				} else {
					// No matching provider found or models removed entirely; drop any prior registration.
					GlobalModelRegistry().UnregisterClient(a.ID)
				}
				return
			}
		}
	}
	models = applyOAuthModelAlias(s.cfg, provider, authKind, models)
	key := provider
	if key == "" {
		key = strings.ToLower(strings.TrimSpace(a.Provider))
	}
	models = s.appendPluginModels(key, models)
	if len(models) > 0 {
		s.registerResolvedModelsForAuth(a, key, applyModelPrefixes(models, a.Prefix, s.cfg != nil && s.cfg.ForceModelPrefix))
		return
	}

	GlobalModelRegistry().UnregisterClient(a.ID)
}

// refreshModelRegistrationForAuth re-applies the latest model registration for
// one auth and reconciles any concurrent auth changes that race with the
// refresh. Callers are expected to pre-filter provider membership.
//
// Re-registration is deliberate: registry cooldown/suspension state is treated
// as part of the previous registration snapshot and is cleared when the auth is
// rebound to the refreshed model catalog.
func (s *Service) refreshModelRegistrationForAuth(current *coreauth.Auth) bool {
	if s == nil || s.coreManager == nil || current == nil || current.ID == "" {
		return false
	}

	ctx := context.Background()
	if !current.Disabled {
		s.ensureExecutorsForAuth(current)
	}
	s.registerModelsForAuth(ctx, current)
	s.coreManager.ReconcileRegistryModelStates(ctx, current.ID)

	latest, ok := s.latestAuthForModelRegistration(current.ID)
	if !ok || latest.Disabled {
		GlobalModelRegistry().UnregisterClient(current.ID)
		s.coreManager.RefreshSchedulerEntry(current.ID)
		return false
	}

	// Re-apply the latest auth snapshot so concurrent auth updates cannot leave
	// stale model registrations behind. This may duplicate registration work when
	// no auth fields changed, but keeps the refresh path simple and correct.
	s.ensureExecutorsForAuth(latest)
	s.registerModelsForAuth(ctx, latest)
	s.coreManager.ReconcileRegistryModelStates(ctx, latest.ID)
	s.coreManager.RefreshSchedulerEntry(current.ID)
	return true
}

// latestAuthForModelRegistration returns the latest auth snapshot regardless of
// provider membership. Callers use this after a registration attempt to restore
// whichever state currently owns the client ID in the global registry.
func (s *Service) latestAuthForModelRegistration(authID string) (*coreauth.Auth, bool) {
	if s == nil || s.coreManager == nil || authID == "" {
		return nil, false
	}
	auth, ok := s.coreManager.GetByID(authID)
	if !ok || auth == nil || auth.ID == "" {
		return nil, false
	}
	return auth, true
}

func (s *Service) resolveConfigClaudeKey(auth *coreauth.Auth) *config.ClaudeKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.ClaudeKey {
		entry := &s.cfg.ClaudeKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && attrBase != "" {
			if strings.EqualFold(cfgKey, attrKey) && strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range s.cfg.ClaudeKey {
			entry := &s.cfg.ClaudeKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func (s *Service) resolveConfigGeminiKey(auth *coreauth.Auth) *config.GeminiKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.GeminiKey {
		entry := &s.cfg.GeminiKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	return nil
}

func (s *Service) resolveConfigVertexCompatKey(auth *coreauth.Auth) *config.VertexCompatKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.VertexCompatAPIKey {
		entry := &s.cfg.VertexCompatAPIKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	if attrKey != "" {
		for i := range s.cfg.VertexCompatAPIKey {
			entry := &s.cfg.VertexCompatAPIKey[i]
			if strings.EqualFold(strings.TrimSpace(entry.APIKey), attrKey) {
				return entry
			}
		}
	}
	return nil
}

func (s *Service) resolveConfigCodexKey(auth *coreauth.Auth) *config.CodexKey {
	if auth == nil || s.cfg == nil {
		return nil
	}
	var attrKey, attrBase string
	if auth.Attributes != nil {
		attrKey = strings.TrimSpace(auth.Attributes["api_key"])
		attrBase = strings.TrimSpace(auth.Attributes["base_url"])
	}
	for i := range s.cfg.CodexKey {
		entry := &s.cfg.CodexKey[i]
		cfgKey := strings.TrimSpace(entry.APIKey)
		cfgBase := strings.TrimSpace(entry.BaseURL)
		if attrKey != "" && strings.EqualFold(cfgKey, attrKey) {
			if cfgBase == "" || strings.EqualFold(cfgBase, attrBase) {
				return entry
			}
			continue
		}
		if attrKey == "" && attrBase != "" && strings.EqualFold(cfgBase, attrBase) {
			return entry
		}
	}
	return nil
}

func (s *Service) oauthExcludedModels(provider, authKind string) []string {
	cfg := s.cfg
	if cfg == nil {
		return nil
	}
	authKindKey := strings.ToLower(strings.TrimSpace(authKind))
	providerKey := strings.ToLower(strings.TrimSpace(provider))
	if authKindKey == "apikey" {
		return nil
	}
	return cfg.OAuthExcludedModels[providerKey]
}

func applyExcludedModels(models []*ModelInfo, excluded []string) []*ModelInfo {
	if len(models) == 0 || len(excluded) == 0 {
		return models
	}

	patterns := make([]string, 0, len(excluded))
	for _, item := range excluded {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			patterns = append(patterns, strings.ToLower(trimmed))
		}
	}
	if len(patterns) == 0 {
		return models
	}

	filtered := make([]*ModelInfo, 0, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		modelID := strings.ToLower(strings.TrimSpace(model.ID))
		blocked := false
		for _, pattern := range patterns {
			if matchWildcard(pattern, modelID) {
				blocked = true
				break
			}
		}
		if !blocked {
			filtered = append(filtered, model)
		}
	}
	return filtered
}

func applyModelPrefixes(models []*ModelInfo, prefix string, forceModelPrefix bool) []*ModelInfo {
	trimmedPrefix := strings.TrimSpace(prefix)
	if trimmedPrefix == "" || len(models) == 0 {
		return models
	}

	out := make([]*ModelInfo, 0, len(models)*2)
	seen := make(map[string]struct{}, len(models)*2)

	addModel := func(model *ModelInfo) {
		if model == nil {
			return
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		out = append(out, model)
	}

	for _, model := range models {
		if model == nil {
			continue
		}
		baseID := strings.TrimSpace(model.ID)
		if baseID == "" {
			continue
		}
		if !forceModelPrefix || trimmedPrefix == baseID {
			addModel(model)
		}
		clone := *model
		clone.ID = trimmedPrefix + "/" + baseID
		addModel(&clone)
	}
	return out
}

// matchWildcard performs case-insensitive wildcard matching where '*' matches any substring.
func matchWildcard(pattern, value string) bool {
	if pattern == "" {
		return false
	}

	// Fast path for exact match (no wildcard present).
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	parts := strings.Split(pattern, "*")
	// Handle prefix.
	if prefix := parts[0]; prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = value[len(prefix):]
	}

	// Handle suffix.
	if suffix := parts[len(parts)-1]; suffix != "" {
		if !strings.HasSuffix(value, suffix) {
			return false
		}
		value = value[:len(value)-len(suffix)]
	}

	// Handle middle segments in order.
	for i := 1; i < len(parts)-1; i++ {
		segment := parts[i]
		if segment == "" {
			continue
		}
		idx := strings.Index(value, segment)
		if idx < 0 {
			return false
		}
		value = value[idx+len(segment):]
	}

	return true
}

type modelEntry interface {
	GetName() string
	GetAlias() string
}

func buildOpenAICompatibilityConfigModels(compat *config.OpenAICompatibility) []*ModelInfo {
	if compat == nil || len(compat.Models) == 0 {
		return nil
	}
	now := time.Now().Unix()
	models := make([]*ModelInfo, 0, len(compat.Models))
	for i := range compat.Models {
		model := compat.Models[i]
		modelID := strings.TrimSpace(model.Alias)
		if modelID == "" {
			modelID = strings.TrimSpace(model.Name)
		}
		if modelID == "" {
			continue
		}
		modelType := "openai-compatibility"
		if model.Image {
			modelType = registry.OpenAIImageModelType
		}
		thinking := model.Thinking
		if thinking == nil && !model.Image {
			thinking = &registry.ThinkingSupport{Levels: []string{"low", "medium", "high"}}
		}
		models = append(models, &ModelInfo{
			ID:          modelID,
			Object:      "model",
			Created:     now,
			OwnedBy:     compat.Name,
			Type:        modelType,
			DisplayName: modelID,
			UserDefined: false,
			Thinking:    thinking,
		})
	}
	return models
}

func buildConfigModels[T modelEntry](models []T, ownedBy, modelType string) []*ModelInfo {
	if len(models) == 0 {
		return nil
	}
	now := time.Now().Unix()
	out := make([]*ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for i := range models {
		model := models[i]
		name := strings.TrimSpace(model.GetName())
		alias := strings.TrimSpace(model.GetAlias())
		if alias == "" {
			alias = name
		}
		if alias == "" {
			continue
		}
		key := strings.ToLower(alias)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		display := name
		if display == "" {
			display = alias
		}
		info := &ModelInfo{
			ID:          alias,
			Object:      "model",
			Created:     now,
			OwnedBy:     ownedBy,
			Type:        modelType,
			DisplayName: display,
			UserDefined: true,
		}
		if name != "" {
			if upstream := registry.LookupStaticModelInfo(name); upstream != nil && upstream.Thinking != nil {
				info.Thinking = upstream.Thinking
			}
		}
		out = append(out, info)
	}
	return out
}

func buildVertexCompatConfigModels(entry *config.VertexCompatKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "google", "vertex")
}

func buildGeminiConfigModels(entry *config.GeminiKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "google", "gemini")
}

func buildClaudeConfigModels(entry *config.ClaudeKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return buildConfigModels(entry.Models, "anthropic", "claude")
}

func buildCodexConfigModels(entry *config.CodexKey) []*ModelInfo {
	if entry == nil {
		return nil
	}
	return registry.WithCodexBuiltins(buildConfigModels(entry.Models, "openai", "openai"))
}

func rewriteModelInfoName(name, oldID, newID string) string {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return name
	}
	oldID = strings.TrimSpace(oldID)
	newID = strings.TrimSpace(newID)
	if oldID == "" || newID == "" {
		return name
	}
	if strings.EqualFold(oldID, newID) {
		return name
	}
	if strings.EqualFold(trimmed, oldID) {
		return newID
	}
	if strings.HasSuffix(trimmed, "/"+oldID) {
		prefix := strings.TrimSuffix(trimmed, oldID)
		return prefix + newID
	}
	if trimmed == "models/"+oldID {
		return "models/" + newID
	}
	return name
}

func applyOAuthModelAlias(cfg *config.Config, provider, authKind string, models []*ModelInfo) []*ModelInfo {
	if cfg == nil || len(models) == 0 {
		return models
	}
	channel := coreauth.OAuthModelAliasChannel(provider, authKind)
	if channel == "" || len(cfg.OAuthModelAlias) == 0 {
		return models
	}
	aliases := cfg.OAuthModelAlias[channel]
	if len(aliases) == 0 {
		return models
	}

	type aliasEntry struct {
		alias string
		fork  bool
	}

	forward := make(map[string][]aliasEntry, len(aliases))
	for i := range aliases {
		name := strings.TrimSpace(aliases[i].Name)
		alias := strings.TrimSpace(aliases[i].Alias)
		if name == "" || alias == "" {
			continue
		}
		if strings.EqualFold(name, alias) {
			continue
		}
		key := strings.ToLower(name)
		forward[key] = append(forward[key], aliasEntry{alias: alias, fork: aliases[i].Fork})
	}
	if len(forward) == 0 {
		return models
	}

	out := make([]*ModelInfo, 0, len(models))
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if model == nil {
			continue
		}
		id := strings.TrimSpace(model.ID)
		if id == "" {
			continue
		}
		key := strings.ToLower(id)
		entries := forward[key]
		if len(entries) == 0 {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model)
			continue
		}

		keepOriginal := false
		for _, entry := range entries {
			if entry.fork {
				keepOriginal = true
				break
			}
		}
		if keepOriginal {
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				out = append(out, model)
			}
		}

		addedAlias := false
		for _, entry := range entries {
			mappedID := strings.TrimSpace(entry.alias)
			if mappedID == "" {
				continue
			}
			if strings.EqualFold(mappedID, id) {
				continue
			}
			aliasKey := strings.ToLower(mappedID)
			if _, exists := seen[aliasKey]; exists {
				continue
			}
			seen[aliasKey] = struct{}{}
			clone := *model
			clone.ID = mappedID
			if clone.Name != "" {
				clone.Name = rewriteModelInfoName(clone.Name, id, mappedID)
			}
			out = append(out, &clone)
			addedAlias = true
		}

		if !keepOriginal && !addedAlias {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, model)
		}
	}
	return out
}
