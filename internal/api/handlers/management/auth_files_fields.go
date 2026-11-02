package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	xaiauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/xai"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialweight"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher/synthesizer"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// PatchAuthFileStatus toggles the disabled state of an auth file
func (h *Handler) PatchAuthFileStatus(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req struct {
		Name      string `json:"name"`
		AuthIndex string `json:"auth_index"`
		Disabled  *bool  `json:"disabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(err, http.StatusBadRequest), gin.H{"error": "invalid request body"})
		return
	}

	name := strings.TrimSpace(req.Name)
	authIndex := strings.TrimSpace(req.AuthIndex)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Disabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "disabled is required"})
		return
	}

	h.authStatusMu.Lock()
	locked := true
	defer func() {
		if locked {
			h.authStatusMu.Unlock()
		}
	}()

	ctx := c.Request.Context()

	targetAuth, _ := h.lookupAuthFile(name, authIndex)
	if targetAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if coreauth.IsPluginVirtualAuth(targetAuth) {
		// Allow status changes only when targeting the source auth file name, matching delete semantics.
		// Expanded virtual project auths still cannot be modified independently.
		if !isPluginVirtualSourceDelete(name, targetAuth) {
			c.JSON(http.StatusConflict, gin.H{"error": errPluginVirtualAuth.Error()})
			return
		}
		hookAuths, errPatch := h.patchPluginVirtualSourceStatus(ctx, targetAuth, *req.Disabled)
		if errPatch != nil {
			status := http.StatusInternalServerError
			if errors.Is(errPatch, errAuthFileNotFound) || os.IsNotExist(errPatch) {
				status = http.StatusNotFound
			}
			c.JSON(status, gin.H{"error": errPatch.Error()})
			return
		}
		locked = false
		h.authStatusMu.Unlock()
		if errHook := h.invokePostAuthPersistHooks(ctx, hookAuths); errHook != nil {
			log.Errorf("post-auth persist hook failed for plugin virtual source status update on %s: %v", targetAuth.ID, errHook)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to synchronize plugin virtual auth: %v", errHook)})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "disabled": *req.Disabled})
		return
	}

	if coreauth.IsConfigAPIKeyAuth(targetAuth) {
		h.mu.Lock()
		handled, errToggle := toggleConfigAPIKeyExcludedAll(h.cfg, targetAuth, *req.Disabled)
		if errToggle != nil {
			h.mu.Unlock()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update config api key: %v", errToggle)})
			return
		}
		if !handled {
			h.mu.Unlock()
			c.JSON(http.StatusNotFound, gin.H{"error": "config api key entry not found"})
			return
		}
		cfgSnapshot, okSnapshot := h.saveConfigAndSnapshotLocked(c)
		h.mu.Unlock()
		if !okSnapshot {
			return
		}
		h.reloadConfigAfterManagementSave(ctx, cfgSnapshot)
		if h.tokenStore != nil {
			_ = h.tokenStore.Delete(ctx, targetAuth.ID)
		}
		c.JSON(http.StatusOK, gin.H{
			"status":           "ok",
			"disabled":         *req.Disabled,
			"via":              "config:excluded-models",
			"excluded_pattern": configAPIKeyDisablePattern,
		})
		return
	}

	updatedAuth, committed, errModify := h.authManager.Modify(ctx, targetAuth.ID, targetAuth.RegistrationEpoch, func(current *coreauth.Auth) error {
		applyAuthDisabledState(current, *req.Disabled)
		return nil
	})
	if errModify != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth: %v", errModify)})
		return
	}
	if !committed || updatedAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	locked = false
	h.authStatusMu.Unlock()
	if errHook := h.invokePostAuthPersistHooks(ctx, []*coreauth.Auth{updatedAuth}); errHook != nil {
		log.Errorf("post-auth persist hook failed for status update on %s: %v", targetAuth.ID, errHook)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to synchronize auth runtime: %v", errHook)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "disabled": *req.Disabled})
}

// patchPluginVirtualSourceStatus toggles disabled on a plugin multi-auth source file and all
// runtime auths expanded from it. Virtual project children cannot be toggled independently.
func (h *Handler) patchPluginVirtualSourceStatus(ctx context.Context, targetAuth *coreauth.Auth, disabled bool) ([]*coreauth.Auth, error) {
	if h == nil || h.authManager == nil || targetAuth == nil {
		return nil, fmt.Errorf("core auth manager unavailable")
	}
	sourcePath := strings.TrimSpace(authAttribute(targetAuth, coreauth.AttributeVirtualSource))
	if sourcePath == "" {
		sourcePath = strings.TrimSpace(authAttribute(targetAuth, "path"))
	}
	if sourcePath == "" {
		return nil, errPluginVirtualAuth
	}
	if errWrite := setSourceAuthFileDisabled(sourcePath, disabled); errWrite != nil {
		if os.IsNotExist(errWrite) {
			return nil, errAuthFileNotFound
		}
		return nil, fmt.Errorf("failed to update source auth file: %w", errWrite)
	}
	now := time.Now()
	hookAuths := make([]*coreauth.Auth, 0)
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if !sameAuthFilePath(authAttribute(auth, "path"), sourcePath) &&
			!sameAuthFilePath(authAttribute(auth, coreauth.AttributeVirtualSource), sourcePath) {
			continue
		}
		updated, committed, errUpdate := h.authManager.Modify(ctx, auth.ID, auth.RegistrationEpoch, func(current *coreauth.Auth) error {
			applyAuthDisabledState(current, disabled)
			current.UpdatedAt = now
			return nil
		})
		if errUpdate != nil {
			return nil, fmt.Errorf("failed to update auth %s: %w", auth.ID, errUpdate)
		}
		if !committed || updated == nil {
			continue
		}
		hookAuths = append(hookAuths, updated)
	}
	return hookAuths, nil
}

func (h *Handler) invokePostAuthPersistHooks(ctx context.Context, auths []*coreauth.Auth) error {
	if h == nil || h.postAuthPersistHook == nil {
		return nil
	}
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		if errHook := h.postAuthPersistHook(ctx, auth); errHook != nil {
			return errHook
		}
	}
	return nil
}

func setSourceAuthFileDisabled(path string, disabled bool) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("source auth path is empty")
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		return errRead
	}
	metadata := make(map[string]any)
	if len(bytes.TrimSpace(data)) > 0 {
		if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
			return fmt.Errorf("invalid auth file: %w", errUnmarshal)
		}
	}
	if metadata == nil {
		metadata = make(map[string]any)
	}
	coreauth.NormalizeCredentialMetadata(metadata)
	metadata["disabled"] = disabled
	raw, errMarshal := json.Marshal(metadata)
	if errMarshal != nil {
		return fmt.Errorf("marshal auth file: %w", errMarshal)
	}
	if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
		return errWrite
	}
	return nil
}

func applyAuthDisabledState(auth *coreauth.Auth, disabled bool) {
	if auth == nil {
		return
	}
	auth.Disabled = disabled
	if disabled {
		auth.Status = coreauth.StatusDisabled
		auth.StatusMessage = "disabled via management API"
	} else {
		auth.Status = coreauth.StatusActive
		auth.StatusMessage = ""
	}
	auth.UpdatedAt = time.Now()
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["disabled"] = disabled
}

// PatchAuthFileFields updates arbitrary metadata fields of an auth file.
func (h *Handler) PatchAuthFileFields(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}

	var req map[string]json.RawMessage
	decoder := json.NewDecoder(c.Request.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&req); err != nil {
		c.JSON(clienterror.HTTPStatusFromErrorOr(err, http.StatusBadRequest), gin.H{"error": "invalid request body"})
		return
	}

	nameRaw, ok := req["name"]
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	var nameValue string
	if err := json.Unmarshal(nameRaw, &nameValue); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	name := strings.TrimSpace(nameValue)
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	delete(req, "name")
	var errNormalize error
	req, errNormalize = normalizeAuthFilePatchFields(req)
	if errNormalize != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": errNormalize.Error()})
		return
	}
	intPatches := make(map[string]authFileIntPatch, len(authFileIntPatchKeys))
	for _, key := range authFileIntPatchKeys {
		patch, errPatch := decodeAuthFileIntPatch(req, key, key == "request_retry")
		if errPatch != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errPatch.Error()})
			return
		}
		intPatches[key] = patch
	}
	for key := range req {
		if _, handled := intPatches[strings.TrimSpace(key)]; handled {
			delete(req, key)
		}
	}

	ctx := c.Request.Context()

	// Find auth by name or ID
	var targetAuth *coreauth.Auth
	if auth, ok := h.authManager.GetByID(name); ok {
		targetAuth = auth
	} else {
		auths := h.authManager.List()
		for _, auth := range auths {
			if auth.FileName == name {
				targetAuth = auth
				break
			}
		}
	}

	// Config-sourced credentials are managed through config endpoints, not as auth files.
	if targetAuth == nil || targetAuth.AuthSourceKind() == coreauth.AuthSourceConfig {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if coreauth.IsPluginVirtualAuth(targetAuth) {
		c.JSON(http.StatusConflict, gin.H{"error": errPluginVirtualAuth.Error()})
		return
	}

	updatedAuth, committed, errModify := h.authManager.Modify(ctx, targetAuth.ID, targetAuth.RegistrationEpoch, func(current *coreauth.Auth) error {
		return h.applyAuthFileFieldsPatch(current, req, intPatches)
	})
	if errModify != nil {
		var patchErr *authFileFieldPatchError
		if errors.As(errModify, &patchErr) {
			c.JSON(http.StatusBadRequest, gin.H{"error": patchErr.message})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to update auth: %v", errModify)})
		return
	}
	if !committed || updatedAuth == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "auth file not found"})
		return
	}
	if h.postAuthPersistHook != nil {
		if errHook := h.postAuthPersistHook(ctx, updatedAuth); errHook != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("post-auth persist hook failed: %v", errHook)})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type authFileFieldPatchError struct {
	message string
}

func (e *authFileFieldPatchError) Error() string {
	return e.message
}

// applyAuthFileFieldsPatch mutates targetAuth with the decoded patch. It runs inside
// authManager.Modify, so every rejection is an *authFileFieldPatchError (HTTP 400).
func (h *Handler) applyAuthFileFieldsPatch(targetAuth *coreauth.Auth, req map[string]json.RawMessage, intPatches map[string]authFileIntPatch) error {
	coreauth.NormalizeCredentialMetadata(targetAuth.Metadata)

	changed := false
	touchedRoots := make(map[string]struct{}, len(req))
	for key, rawValue := range req {
		fieldPath := strings.TrimSpace(key)
		if fieldPath == "" {
			return &authFileFieldPatchError{message: "field name is required"}
		}
		value, errDecode := decodeAuthFileFieldValue(rawValue)
		if errDecode != nil {
			return &authFileFieldPatchError{message: fmt.Sprintf("invalid field %s", fieldPath)}
		}
		if rootAuthFileField(fieldPath) == "excluded_models" {
			if fieldPath != "excluded_models" {
				return &authFileFieldPatchError{message: "excluded_models does not support nested fields"}
			}
			if value != nil {
				models, okModels := value.([]any)
				validModels := okModels
				for _, model := range models {
					if _, okString := model.(string); !okString {
						validModels = false
						break
					}
				}
				if !validModels {
					return &authFileFieldPatchError{message: "excluded_models must be a string array or null"}
				}
			}
		}
		if targetAuth.Metadata == nil {
			targetAuth.Metadata = make(map[string]any)
		}

		if fieldPath == coreauth.AttributeWeight {
			if value == nil {
				delete(targetAuth.Metadata, coreauth.AttributeWeight)
			} else {
				if _, okNumber := value.(json.Number); !okNumber {
					return &authFileFieldPatchError{message: "weight must be an integer"}
				}
				weight, errWeight := credentialweight.ParseValue(value)
				if errWeight != nil {
					return &authFileFieldPatchError{message: errWeight.Error()}
				}
				targetAuth.Metadata[coreauth.AttributeWeight] = weight
			}
		} else if rootAuthFileField(fieldPath) == coreauth.AttributeWeight {
			return &authFileFieldPatchError{message: "weight does not support nested fields"}
		} else if fieldPath == "headers" {
			applyAuthFileHeadersPatch(targetAuth, value)
		} else if errSet := setAuthFileMetadataValue(targetAuth.Metadata, fieldPath, value); errSet != nil {
			return &authFileFieldPatchError{message: errSet.Error()}
		}
		if root := rootAuthFileField(fieldPath); root != "" {
			touchedRoots[root] = struct{}{}
		}
		changed = true
	}
	for _, key := range authFileIntPatchKeys {
		if applyAuthFileIntPatch(targetAuth, key, intPatches[key]) {
			changed = true
		}
	}
	if _, touched := touchedRoots["device_profile"]; touched {
		if errProfile := syncAuthFileClaudeDeviceProfile(targetAuth); errProfile != nil {
			return &authFileFieldPatchError{message: errProfile.Error()}
		}
	}
	if _, touched := touchedRoots["active_hours"]; touched {
		if errHours := validateAuthFileActiveHours(targetAuth); errHours != nil {
			return &authFileFieldPatchError{message: errHours.Error()}
		}
	}
	if _, touched := touchedRoots["proxy_pool_label"]; touched {
		if errLabel := h.validateAuthFileProxyPoolLabel(targetAuth); errLabel != nil {
			return &authFileFieldPatchError{message: errLabel.Error()}
		}
	}
	if changed {
		syncAuthFileMetadataFields(targetAuth, touchedRoots)
		if _, touched := touchedRoots["excluded_models"]; touched {
			excluded, errExcluded := synthesizer.ExtractExcludedModelsFromMetadata(targetAuth.Metadata)
			if errExcluded != nil {
				return &authFileFieldPatchError{message: errExcluded.Error()}
			}
			// ApplyAuthExcludedModelsMeta never clears attributes, so drop stale values first.
			delete(targetAuth.Attributes, "excluded_models")
			delete(targetAuth.Attributes, "excluded_models_hash")
			// Store only the credential's own rules; global rules are resolved at model registration.
			// An empty authKind keeps the existing auth_kind attribute unchanged.
			synthesizer.ApplyAuthExcludedModelsMeta(targetAuth, excluded, "")
		}
	}

	if !changed {
		return &authFileFieldPatchError{message: "no fields to update"}
	}

	targetAuth.UpdatedAt = time.Now()
	return nil
}

func decodeAuthFileFieldValue(raw json.RawMessage) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// authFileIntPatchKeys are the integer metadata fields decoded out-of-band by PatchAuthFileFields.
var authFileIntPatchKeys = []string{"request_retry", "rpm", "tpm", "max_concurrent", "rpd", "tpd", "max_sessions"}

type authFileIntPatch struct {
	Set   bool
	Value *int
}

// applyAuthFileIntPatch writes or deletes an integer metadata field and reports whether it changed anything.
func applyAuthFileIntPatch(auth *coreauth.Auth, key string, patch authFileIntPatch) bool {
	if auth == nil || !patch.Set {
		return false
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	if patch.Value == nil {
		delete(auth.Metadata, key)
	} else {
		auth.Metadata[key] = *patch.Value
	}
	return true
}

func normalizeAuthFilePatchFields(fields map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	normalized := make(map[string]json.RawMessage, len(fields))
	originalNames := make(map[string]string, len(fields))
	canonicalNames := make(map[string]bool, len(fields))
	for key, value := range fields {
		parts := strings.Split(strings.TrimSpace(key), ".")
		for index := range parts {
			parts[index] = strings.TrimSpace(parts[index])
		}
		originalRoot := parts[0]
		parts[0] = coreauth.CanonicalCredentialMetadataKey(originalRoot)
		canonicalPath := strings.Join(parts, ".")
		if original, exists := originalNames[canonicalPath]; exists {
			currentCanonical := originalRoot == parts[0]
			if canonicalNames[canonicalPath] != currentCanonical {
				if currentCanonical {
					normalized[canonicalPath] = value
					originalNames[canonicalPath] = key
					canonicalNames[canonicalPath] = true
				}
				continue
			}
			return nil, fmt.Errorf("auth file fields %q and %q refer to the same field", original, key)
		}
		normalized[canonicalPath] = value
		originalNames[canonicalPath] = key
		canonicalNames[canonicalPath] = originalRoot == parts[0]
	}
	return normalized, nil
}

// decodeAuthFileIntPatch extracts an integer-or-null field. When negativeClears is true a
// negative value deletes the override (legacy request_retry semantics); otherwise it is rejected.
func decodeAuthFileIntPatch(fields map[string]json.RawMessage, key string, negativeClears bool) (authFileIntPatch, error) {
	var raw json.RawMessage
	found := false
	for fieldKey, value := range fields {
		fieldPath := strings.TrimSpace(fieldKey)
		fieldRoot := rootAuthFileField(fieldPath)
		if fieldRoot == key && fieldPath != fieldRoot {
			return authFileIntPatch{}, fmt.Errorf("%s does not support nested fields", key)
		}
		if fieldPath == key {
			found = true
			raw = value
		}
	}
	if !found {
		return authFileIntPatch{}, nil
	}
	errInvalid := fmt.Errorf("%s must be an integer or null", key)
	if !negativeClears {
		errInvalid = fmt.Errorf("%s must be a non-negative integer or null", key)
	}
	value, errDecode := decodeAuthFileFieldValue(raw)
	if errDecode != nil {
		return authFileIntPatch{}, errInvalid
	}
	if value == nil {
		return authFileIntPatch{Set: true}, nil
	}
	number, okNumber := value.(json.Number)
	if !okNumber {
		return authFileIntPatch{}, errInvalid
	}
	parsed, errInt := number.Int64()
	if errInt != nil {
		return authFileIntPatch{}, errInvalid
	}
	normalized := int(parsed)
	if int64(normalized) != parsed {
		return authFileIntPatch{}, errInvalid
	}
	if normalized < 0 {
		if negativeClears {
			return authFileIntPatch{Set: true}, nil
		}
		return authFileIntPatch{}, errInvalid
	}
	return authFileIntPatch{Set: true, Value: &normalized}, nil
}

func rootAuthFileField(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if idx := strings.Index(path, "."); idx >= 0 {
		return strings.TrimSpace(path[:idx])
	}
	return path
}

func setAuthFileMetadataValue(metadata map[string]any, path string, value any) error {
	if metadata == nil {
		return fmt.Errorf("metadata is nil")
	}
	parts := strings.Split(path, ".")
	current := metadata
	for i, rawPart := range parts {
		part := strings.TrimSpace(rawPart)
		if part == "" {
			return fmt.Errorf("invalid field path: %s", path)
		}
		if i == len(parts)-1 {
			current[part] = value
			return nil
		}
		next, ok := current[part].(map[string]any)
		if !ok {
			next = make(map[string]any)
			current[part] = next
		}
		current = next
	}
	return nil
}

func applyAuthFileHeadersPatch(auth *coreauth.Auth, value any) {
	if auth == nil {
		return
	}
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	headersPatch, ok := authFileHeadersStringMap(value)
	if !ok {
		auth.Metadata["headers"] = value
		return
	}

	existingHeaders := coreauth.ExtractCustomHeadersFromMetadata(auth.Metadata)
	nextHeaders := make(map[string]string, len(existingHeaders))
	for key, val := range existingHeaders {
		nextHeaders[key] = val
	}
	for key, value := range headersPatch {
		name := strings.TrimSpace(key)
		if name == "" {
			continue
		}
		val := strings.TrimSpace(value)
		if val == "" {
			delete(nextHeaders, name)
			continue
		}
		nextHeaders[name] = val
	}

	if len(nextHeaders) == 0 {
		delete(auth.Metadata, "headers")
		return
	}
	metaHeaders := make(map[string]any, len(nextHeaders))
	for key, value := range nextHeaders {
		metaHeaders[key] = value
	}
	auth.Metadata["headers"] = metaHeaders
}

func authFileHeadersStringMap(value any) (map[string]string, bool) {
	switch typed := value.(type) {
	case map[string]string:
		return typed, true
	case map[string]any:
		out := make(map[string]string, len(typed))
		for key, rawValue := range typed {
			value, ok := rawValue.(string)
			if !ok {
				return nil, false
			}
			out[key] = value
		}
		return out, true
	default:
		return nil, false
	}
}

func syncAuthFileMetadataFields(auth *coreauth.Auth, touchedRoots map[string]struct{}) {
	if auth == nil || len(touchedRoots) == 0 {
		return
	}
	if _, ok := touchedRoots["prefix"]; ok {
		if prefix, okString := auth.Metadata["prefix"].(string); okString {
			auth.Prefix = strings.TrimSpace(prefix)
		}
	}
	if _, ok := touchedRoots["proxy_url"]; ok {
		// An explicit proxy replaces a proxy-pool assignment; drop the pool marks so
		// the persisted state and the identity line stop describing the pool line.
		if auth.Attributes != nil {
			delete(auth.Attributes, coreauth.AttributeProxyPool)
			delete(auth.Attributes, coreauth.AttributeProxyPoolLabel)
		}
		if proxyURL, okString := auth.Metadata["proxy_url"].(string); okString {
			auth.ProxyURL = strings.TrimSpace(proxyURL)
		}
	}
	if _, ok := touchedRoots["headers"]; ok {
		syncAuthFileHeaderAttributes(auth)
	}
	if _, ok := touchedRoots["priority"]; ok {
		syncAuthFilePriorityAttribute(auth)
	}
	if _, ok := touchedRoots[coreauth.AttributeWeight]; ok {
		syncAuthFileWeightAttribute(auth)
	}
	if _, ok := touchedRoots["note"]; ok {
		syncAuthFileNoteAttribute(auth)
	}
	if _, ok := touchedRoots["websockets"]; ok {
		syncAuthFileWebsocketsAttribute(auth)
	}
	if _, ok := touchedRoots["disabled"]; ok {
		syncAuthFileDisabledState(auth)
	}
	if _, ok := touchedRoots["plan_type"]; ok {
		syncAuthFilePlanTypeAttribute(auth)
	} else if _, ok := touchedRoots["id_token"]; ok {
		syncAuthFilePlanTypeAttribute(auth)
	}
}

func syncAuthFilePlanTypeAttribute(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	newPlanType := ""
	if auth.Metadata != nil {
		if ptRaw, ok := auth.Metadata["plan_type"].(string); ok && strings.TrimSpace(ptRaw) != "" {
			newPlanType = strings.TrimSpace(ptRaw)
		} else if idTokenRaw, ok := auth.Metadata["id_token"].(string); ok && strings.TrimSpace(idTokenRaw) != "" {
			if claims, errParse := codex.ParseJWTToken(idTokenRaw); errParse == nil && claims != nil {
				newPlanType = claims.GetPlanType()
			} else {
				newPlanType = codex.DefaultPlanType
			}
		}
	}
	if newPlanType != "" {
		auth.Attributes["plan_type"] = newPlanType
	} else {
		delete(auth.Attributes, "plan_type")
	}
}

// syncAuthFileClaudeDeviceProfile validates the patched device_profile object and
// re-projects it into the attributes the Claude executor reads. A typo is rejected
// with 400 rather than silently inheriting the global baseline at request time.
func syncAuthFileClaudeDeviceProfile(auth *coreauth.Auth) error {
	if auth == nil {
		return nil
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	for _, key := range []string{
		coreauth.AttributeClaudeDeviceUserAgent, coreauth.AttributeClaudeDevicePackageVersion,
		coreauth.AttributeClaudeDeviceRuntimeVersion, coreauth.AttributeClaudeDeviceOS, coreauth.AttributeClaudeDeviceArch,
	} {
		delete(auth.Attributes, key)
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "claude") {
		return nil
	}
	profile, errDecode := config.ClaudeDeviceProfileValuesFromMetadata(auth.Metadata)
	if errDecode != nil {
		return errDecode
	}
	if profile.IsZero() {
		return nil
	}
	if errValidate := profile.Validate(); errValidate != nil {
		return fmt.Errorf("device_profile: %w", errValidate)
	}
	profile = profile.Trimmed()
	set := func(key, value string) {
		if value != "" {
			auth.Attributes[key] = value
		}
	}
	set(coreauth.AttributeClaudeDeviceUserAgent, profile.UserAgent)
	set(coreauth.AttributeClaudeDevicePackageVersion, profile.PackageVersion)
	set(coreauth.AttributeClaudeDeviceRuntimeVersion, profile.RuntimeVersion)
	set(coreauth.AttributeClaudeDeviceOS, profile.OS)
	set(coreauth.AttributeClaudeDeviceArch, profile.Arch)
	return nil
}

func syncAuthFileHeaderAttributes(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	for key := range auth.Attributes {
		if strings.HasPrefix(key, "header:") {
			delete(auth.Attributes, key)
		}
	}
	for name, value := range coreauth.ExtractCustomHeadersFromMetadata(auth.Metadata) {
		auth.Attributes["header:"+name] = value
	}
}

func syncAuthFilePriorityAttribute(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	priority, ok := authFileIntValue(auth.Metadata["priority"])
	if !ok {
		delete(auth.Attributes, "priority")
		delete(auth.Attributes, coreauth.AttributeFilePriority)
		return
	}
	if auth.Attributes[coreauth.AttributeSourceBackend] == coreauth.AuthSourceFile {
		auth.Attributes[coreauth.AttributeFilePriority] = "true"
	}
	if priority == 0 {
		delete(auth.Attributes, "priority")
		return
	}
	auth.Attributes["priority"] = strconv.Itoa(priority)
}

func syncAuthFileWeightAttribute(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	weight, errWeight := credentialweight.ParseValue(auth.Metadata[coreauth.AttributeWeight])
	if errWeight != nil {
		delete(auth.Attributes, coreauth.AttributeWeight)
		return
	}
	auth.Attributes[coreauth.AttributeWeight] = strconv.FormatInt(weight, 10)
}

func authFileIntValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		if i, err := typed.Int64(); err == nil {
			return int(i), true
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return i, true
		}
	}
	return 0, false
}

func syncAuthFileNoteAttribute(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	note, ok := auth.Metadata["note"].(string)
	if !ok {
		delete(auth.Attributes, "note")
		return
	}
	note = strings.TrimSpace(note)
	if note == "" {
		delete(auth.Attributes, "note")
		return
	}
	auth.Attributes["note"] = note
}

func syncAuthFileWebsocketsAttribute(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	websockets, ok := authFileBoolValue(auth.Metadata["websockets"])
	if !ok {
		delete(auth.Attributes, "websockets")
		return
	}
	auth.Attributes["websockets"] = strconv.FormatBool(websockets)
}

func authFileBoolValue(value any) (bool, bool) {
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, errParse := strconv.ParseBool(strings.TrimSpace(typed))
		if errParse == nil {
			return parsed, true
		}
	}
	return false, false
}

func syncAuthFileDisabledState(auth *coreauth.Auth) {
	if auth == nil {
		return
	}
	disabled, ok := authFileBoolValue(auth.Metadata["disabled"])
	if !ok {
		return
	}
	auth.Disabled = disabled
	if disabled {
		auth.Status = coreauth.StatusDisabled
		if strings.TrimSpace(auth.StatusMessage) == "" {
			auth.StatusMessage = "disabled via management API"
		}
		return
	}
	auth.Status = coreauth.StatusActive
	auth.StatusMessage = ""
}

func (h *Handler) removeAuth(ctx context.Context, id string) {
	if h == nil || h.authManager == nil {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return
	}
	if _, ok := h.authManager.GetByID(id); ok {
		h.authManager.Remove(ctx, id)
		return
	}
	authID := h.authIDForPath(id)
	if authID == "" {
		return
	}
	h.authManager.Remove(ctx, authID)
}

func (h *Handler) removeAuthsForPath(ctx context.Context, path string, fallbackID string) {
	if h == nil || h.authManager == nil {
		return
	}
	removed := false
	for _, auth := range h.authManager.List() {
		if auth == nil {
			continue
		}
		if sameAuthFilePath(authAttribute(auth, "path"), path) || sameAuthFilePath(authAttribute(auth, coreauth.AttributeVirtualSource), path) {
			h.removeAuth(ctx, auth.ID)
			removed = true
		}
	}
	if removed {
		return
	}
	if strings.TrimSpace(fallbackID) != "" {
		h.removeAuth(ctx, fallbackID)
		return
	}
	h.removeAuth(ctx, path)
}

func sameAuthFilePath(left, right string) bool {
	left = cleanAuthFilePath(left)
	right = cleanAuthFilePath(right)
	if left == "" || right == "" {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func cleanAuthFilePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if abs, errAbs := filepath.Abs(path); errAbs == nil && strings.TrimSpace(abs) != "" {
		path = abs
	}
	return filepath.Clean(path)
}

func (h *Handler) deleteTokenRecord(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("auth path is empty")
	}
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return fmt.Errorf("token store unavailable")
	}
	return store.Delete(ctx, path)
}

func (h *Handler) tokenStoreWithBaseDir() coreauth.Store {
	if h == nil {
		return nil
	}
	store := h.tokenStore
	if store == nil {
		store = sdkAuth.GetTokenStore()
		h.tokenStore = store
	}
	if cfg := h.configSnapshot(); cfg != nil {
		if dirSetter, ok := store.(interface{ SetBaseDir(string) }); ok {
			dirSetter.SetBaseDir(cfg.AuthDir)
		}
	}
	return store
}

func (h *Handler) mergeExistingAuthFileMetadata(record *coreauth.Auth) {
	if h == nil || record == nil {
		return
	}
	var existingMap map[string]any

	if cfg := h.configSnapshot(); cfg != nil && strings.TrimSpace(cfg.AuthDir) != "" {
		fullPath := ""
		if record.Attributes != nil {
			fullPath = strings.TrimSpace(record.Attributes[coreauth.AttributePath])
		}
		if fullPath == "" {
			targetFile := record.FileName
			if targetFile == "" {
				targetFile = record.ID
			}
			if targetFile != "" {
				fullPath = filepath.Join(cfg.AuthDir, targetFile)
			}
		}
		if fullPath != "" {
			if raw, errRead := os.ReadFile(fullPath); errRead == nil && len(raw) > 0 {
				_ = json.Unmarshal(raw, &existingMap)
			}
		}
	}

	if existingMap == nil && h.authManager != nil {
		if existing, ok := h.authManager.GetByID(record.ID); ok && existing != nil && existing.Metadata != nil {
			existingMap = existing.Metadata
		} else {
			for _, auth := range h.authManager.List() {
				if auth != nil && auth.FileName == record.FileName && auth.Metadata != nil {
					existingMap = auth.Metadata
					break
				}
			}
		}
	}

	if len(existingMap) > 0 {
		coreauth.MergeExistingAuthMetadata(record, existingMap)
	}
}

func (h *Handler) saveTokenRecord(ctx context.Context, record *coreauth.Auth) (string, error) {
	if record == nil {
		return "", fmt.Errorf("token record is nil")
	}
	h.mergeExistingAuthFileMetadata(record)
	store := h.tokenStoreWithBaseDir()
	if store == nil {
		return "", fmt.Errorf("token store unavailable")
	}
	legacyClaudeCredential, errLegacy := claudeauth.FindMatchingLegacyCredential(ctx, store, record)
	if errLegacy != nil {
		return "", errLegacy
	}
	if legacyClaudeCredential != nil {
		coreauth.MergeExistingAuthMetadata(record, legacyClaudeCredential.Metadata)
	}
	legacyXAICredential, errLegacyXAI := xaiauth.FindMatchingLegacyCredential(ctx, store, record)
	if errLegacyXAI != nil {
		return "", errLegacyXAI
	}
	adoptXAICredential := legacyXAICredential != nil &&
		strings.EqualFold(strings.TrimSpace(record.Provider), "xai") &&
		metadataStringValue(record.Metadata, "email") == "" &&
		metadataStringValue(record.Metadata, "sub") != "" &&
		metadataStringValue(legacyXAICredential.Metadata, "email") != ""
	if adoptXAICredential {
		// The upstream stopped returning the email; keep the account on its
		// richer email-named credential (richest-known name wins) so the next
		// login that returns the email finds the same file again. Renaming is
		// limited to stores that resolve the save path from the record name;
		// every built-in backend (file, git, Postgres, object) exposes the
		// SetBaseDir capability, so unknown stores keep the ordinary
		// migration instead of risking a rename they cannot honor.
		if _, isFileNameStore := store.(interface{ SetBaseDir(string) }); !isFileNameStore {
			adoptXAICredential = false
		} else if disabled, hasDisabled := record.Metadata["disabled"].(bool); hasDisabled && disabled {
			// The destination file deliberately disables this credential; renaming
			// would leave it disabled while the richer file gets deleted, losing
			// the operator's opt-out and the saved credential on re-login.
			adoptXAICredential = false
		}
	}
	if legacyXAICredential != nil {
		coreauth.MergeExistingAuthMetadata(record, legacyXAICredential.Metadata)
	}
	if adoptXAICredential {
		adoptLegacyXAIFileName(record, legacyXAICredential)
	}
	if h.postAuthHook != nil {
		if err := h.postAuthHook(ctx, record); err != nil {
			return "", fmt.Errorf("post-auth hook failed: %w", err)
		}
	}
	savedPath, errSave := store.Save(coreauth.WithAuthCreationIntent(ctx), record)
	if errSave != nil {
		return savedPath, errSave
	}
	if legacyClaudeCredential != nil {
		if strings.TrimSpace(savedPath) == "" {
			return "", fmt.Errorf("canonical Claude credential was not persisted; legacy credential retained")
		}
		legacyID := strings.TrimSpace(legacyClaudeCredential.ID)
		if legacyID == "" {
			legacyID = strings.TrimSpace(legacyClaudeCredential.FileName)
		}
		if errDelete := store.Delete(ctx, legacyID); errDelete != nil {
			return savedPath, fmt.Errorf("canonical Claude credential saved but legacy credential cleanup failed: %w", errDelete)
		}
	}
	if legacyXAICredential != nil && !adoptXAICredential {
		if strings.TrimSpace(savedPath) == "" {
			return "", fmt.Errorf("canonical xAI credential was not persisted; legacy credential retained")
		}
		legacyID := strings.TrimSpace(legacyXAICredential.ID)
		if legacyID == "" {
			legacyID = strings.TrimSpace(legacyXAICredential.FileName)
		}
		if errDelete := store.Delete(ctx, legacyID); errDelete != nil {
			return savedPath, fmt.Errorf("canonical xAI credential saved but legacy credential cleanup failed: %w", errDelete)
		}
	}
	if h.postAuthPersistHook != nil {
		persistedRecord := record
		if data, errRead := os.ReadFile(savedPath); errRead == nil && len(data) > 0 {
			cfg := h.configSnapshot()
			authDir := filepath.Dir(savedPath)
			if cfg != nil && strings.TrimSpace(cfg.AuthDir) != "" {
				authDir = cfg.AuthDir
			}
			auths, errSynthesize := synthesizer.SynthesizeAuthFile(&synthesizer.SynthesisContext{
				Config:           cfg,
				AuthDir:          authDir,
				Now:              time.Now(),
				IDGenerator:      synthesizer.NewStableIDGenerator(),
				PluginAuthParser: h.pluginHost,
			}, savedPath, data)
			if errSynthesize != nil {
				return savedPath, fmt.Errorf("synthesize persisted auth failed: %w", errSynthesize)
			}
			for _, auth := range auths {
				if auth != nil && (auth.ID == record.ID || len(auths) == 1) {
					if len(auths) == 1 && strings.TrimSpace(record.ID) != "" {
						auth.ID = record.ID
					}
					persistedRecord = auth
					break
				}
			}
		}
		if errHook := h.postAuthPersistHook(ctx, persistedRecord); errHook != nil {
			return savedPath, fmt.Errorf("post-auth persist hook failed: %w", errHook)
		}
	} else if h.authManager != nil && strings.TrimSpace(savedPath) != "" {
		if errReg := h.registerAuthFromFileWithID(ctx, savedPath, nil, record.ID); errReg != nil {
			return savedPath, fmt.Errorf("register persisted auth failed: %w", errReg)
		}
	}
	return savedPath, nil
}

// validateAuthFileActiveHours checks a patched active_hours window. An empty string
// stays as an explicit "always on" override; a non-string value is rejected.
func validateAuthFileActiveHours(auth *coreauth.Auth) error {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, present := auth.Metadata["active_hours"]
	if !present {
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return fmt.Errorf("active_hours must be a string like \"08:30-01:00\" or null")
	}
	if _, errParse := config.ParseActiveHours(value); errParse != nil {
		return errParse
	}
	auth.Metadata["active_hours"] = strings.TrimSpace(value)
	return nil
}

// validateAuthFileProxyPoolLabel checks a patched proxy_pool_label against the configured
// pool. An empty string removes the pin so the stable hash assignment applies again.
func (h *Handler) validateAuthFileProxyPoolLabel(auth *coreauth.Auth) error {
	if auth == nil || auth.Metadata == nil {
		return nil
	}
	raw, present := auth.Metadata["proxy_pool_label"]
	if !present {
		return nil
	}
	value, ok := raw.(string)
	if !ok {
		return fmt.Errorf("proxy_pool_label must be a string or null")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		delete(auth.Metadata, "proxy_pool_label")
		return nil
	}
	if _, found := h.proxyPoolEntryByLabel(value); !found {
		return fmt.Errorf("proxy_pool_label %q does not match any proxy-pool entry", value)
	}
	auth.Metadata["proxy_pool_label"] = value
	return nil
}

// proxyPoolEntryByLabel finds a configured proxy-pool entry by its label (case-insensitive).
func (h *Handler) proxyPoolEntryByLabel(label string) (config.ProxyPoolEntry, bool) {
	label = strings.TrimSpace(label)
	if h == nil || h.cfg == nil || label == "" {
		return config.ProxyPoolEntry{}, false
	}
	h.mu.Lock()
	pool := append([]config.ProxyPoolEntry(nil), h.cfg.ProxyPool...)
	h.mu.Unlock()
	for _, entry := range pool {
		if strings.EqualFold(strings.TrimSpace(entry.Label), label) {
			return entry, true
		}
	}
	return config.ProxyPoolEntry{}, false
}

func metadataStringValue(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

// adoptLegacyXAIFileName points a subject-only xAI record at the existing
// email-named credential so the save refreshes that file in place. The token
// storage email is backfilled because SaveTokenToFile merges the record
// metadata over the serialized storage and would otherwise drop the email.
// Path attributes pointing at the superseded subject-named file are cleared
// so the store resolves the adopted name.
func adoptLegacyXAIFileName(record, legacy *coreauth.Auth) {
	legacyFileName := strings.TrimSpace(legacy.FileName)
	if legacyFileName == "" {
		legacyFileName = strings.TrimSpace(legacy.ID)
	}
	if legacyFileName == "" {
		return
	}
	oldBaseName := filepath.Base(strings.TrimSpace(record.FileName))
	if oldBaseName == "" || oldBaseName == "." {
		oldBaseName = filepath.Base(strings.TrimSpace(record.ID))
	}
	record.ID = legacyFileName
	record.FileName = legacyFileName
	if storage, ok := record.Storage.(*xaiauth.TokenStorage); ok && storage != nil {
		if email := metadataStringValue(legacy.Metadata, "email"); email != "" {
			storage.Email = email
		}
	}
	for key, value := range record.Attributes {
		if strings.TrimSpace(value) != "" && strings.EqualFold(filepath.Base(strings.TrimSpace(value)), oldBaseName) {
			delete(record.Attributes, key)
		}
	}
}
