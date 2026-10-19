package service

import (
	"context"
	"log/slog"

	"github.com/ducnt114/gocloak/internal/model"
)

// DefaultEventTypes are the event types Keycloak stores when a realm does
// not configure enabledEventTypes.
var DefaultEventTypes = []string{
	"LOGIN", "LOGIN_ERROR", "REGISTER", "REGISTER_ERROR", "LOGOUT", "LOGOUT_ERROR", "CODE_TO_TOKEN", "CODE_TO_TOKEN_ERROR",
	"CLIENT_LOGIN", "CLIENT_LOGIN_ERROR", "FEDERATED_IDENTITY_LINK", "FEDERATED_IDENTITY_LINK_ERROR",
	"REMOVE_FEDERATED_IDENTITY", "REMOVE_FEDERATED_IDENTITY_ERROR", "UPDATE_EMAIL", "UPDATE_EMAIL_ERROR",
	"UPDATE_PROFILE", "UPDATE_PROFILE_ERROR", "UPDATE_PASSWORD", "UPDATE_PASSWORD_ERROR", "UPDATE_TOTP", "UPDATE_TOTP_ERROR",
	"VERIFY_EMAIL", "VERIFY_EMAIL_ERROR", "VERIFY_PROFILE", "VERIFY_PROFILE_ERROR", "REMOVE_TOTP", "REMOVE_TOTP_ERROR",
	"GRANT_CONSENT", "GRANT_CONSENT_ERROR", "UPDATE_CONSENT", "UPDATE_CONSENT_ERROR", "REVOKE_GRANT", "REVOKE_GRANT_ERROR",
	"SEND_VERIFY_EMAIL", "SEND_VERIFY_EMAIL_ERROR", "SEND_RESET_PASSWORD", "SEND_RESET_PASSWORD_ERROR",
	"SEND_IDENTITY_PROVIDER_LINK", "SEND_IDENTITY_PROVIDER_LINK_ERROR", "RESET_PASSWORD", "RESET_PASSWORD_ERROR",
	"RESTART_AUTHENTICATION", "RESTART_AUTHENTICATION_ERROR", "IDENTITY_PROVIDER_LINK_ACCOUNT", "IDENTITY_PROVIDER_LINK_ACCOUNT_ERROR",
	"IDENTITY_PROVIDER_FIRST_LOGIN", "IDENTITY_PROVIDER_FIRST_LOGIN_ERROR", "IDENTITY_PROVIDER_POST_LOGIN", "IDENTITY_PROVIDER_POST_LOGIN_ERROR",
	"IMPERSONATE", "IMPERSONATE_ERROR", "CUSTOM_REQUIRED_ACTION", "CUSTOM_REQUIRED_ACTION_ERROR", "EXECUTE_ACTIONS", "EXECUTE_ACTIONS_ERROR",
	"EXECUTE_ACTION_TOKEN", "EXECUTE_ACTION_TOKEN_ERROR", "CLIENT_REGISTER", "CLIENT_REGISTER_ERROR", "CLIENT_UPDATE", "CLIENT_UPDATE_ERROR",
	"CLIENT_DELETE", "CLIENT_DELETE_ERROR", "CLIENT_INITIATED_ACCOUNT_LINKING", "CLIENT_INITIATED_ACCOUNT_LINKING_ERROR",
	"TOKEN_EXCHANGE", "TOKEN_EXCHANGE_ERROR", "OAUTH2_DEVICE_AUTH", "OAUTH2_DEVICE_AUTH_ERROR", "OAUTH2_DEVICE_VERIFY_USER_CODE",
	"OAUTH2_DEVICE_VERIFY_USER_CODE_ERROR", "OAUTH2_DEVICE_CODE_TO_TOKEN", "OAUTH2_DEVICE_CODE_TO_TOKEN_ERROR",
	"AUTHREQID_TO_TOKEN", "AUTHREQID_TO_TOKEN_ERROR", "PERMISSION_TOKEN", "DELETE_ACCOUNT", "DELETE_ACCOUNT_ERROR",
	"USER_DISABLED_BY_PERMANENT_LOCKOUT", "USER_DISABLED_BY_TEMPORARY_LOCKOUT", "OAUTH2_EXTENSION_GRANT", "OAUTH2_EXTENSION_GRANT_ERROR",
	"FEDERATED_IDENTITY_OVERRIDE_LINK", "FEDERATED_IDENTITY_OVERRIDE_LINK_ERROR", "UPDATE_CREDENTIAL", "UPDATE_CREDENTIAL_ERROR",
	"REMOVE_CREDENTIAL", "REMOVE_CREDENTIAL_ERROR",
}

// EventListener receives every event of realms that enable it.
type EventListener interface {
	OnEvent(realm *model.Realm, e *model.Event)
	OnAdminEvent(realm *model.Realm, e *model.AdminEvent)
}

// logListener is Keycloak's "jboss-logging" listener: successes at debug
// level, errors as warnings.
type logListener struct{ log *slog.Logger }

func (l logListener) OnEvent(realm *model.Realm, e *model.Event) {
	attrs := []any{"type", e.Type, "realm", realm.Name, "client", e.ClientID, "user", e.UserID, "session", e.SessionID, "ip", e.IPAddress}
	for k, v := range e.Details {
		attrs = append(attrs, k, v)
	}
	if e.Error != "" {
		l.log.Warn("event", append(attrs, "error", e.Error)...)
		return
	}
	l.log.Debug("event", attrs...)
}

func (l logListener) OnAdminEvent(realm *model.Realm, e *model.AdminEvent) {
	l.log.Debug("admin event", "operation", e.OperationType, "resource", e.ResourceType, "path", e.ResourcePath,
		"realm", realm.Name, "authUser", e.AuthUserID, "ip", e.AuthIP)
}

// Listeners returns the registered event listeners by id.
func (s *Service) Listeners() map[string]EventListener {
	l := map[string]EventListener{"jboss-logging": logListener{s.logger()}}
	for id, lis := range s.ExtraListeners {
		l[id] = lis
	}
	return l
}

func (s *Service) eventEnabled(realm *model.Realm, typ string) bool {
	types := realm.Settings.EnabledEventTypes
	if len(types) == 0 {
		types = DefaultEventTypes
	}
	for _, t := range types {
		if t == typ {
			return true
		}
	}
	return false
}

// RecordEvent stores a login event (when the realm saves events) and passes
// it to the realm's listeners. Failures are logged, never returned: events
// must not break logins.
func (s *Service) RecordEvent(ctx context.Context, realm *model.Realm, e *model.Event) {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.Time == 0 {
		e.Time = s.Now().UnixMilli()
	}
	e.RealmID = realm.ID
	if s.EventObserver != nil {
		s.EventObserver(realm, e)
	}
	if realm.Settings.EventsEnabled && s.eventEnabled(realm, e.Type) {
		if err := s.Store.AddEvent(ctx, e); err != nil {
			s.logger().Error("store event", "type", e.Type, "err", err)
		}
	}
	listeners := s.Listeners()
	for _, id := range realm.Settings.EventsListeners {
		if l := listeners[id]; l != nil {
			l.OnEvent(realm, e)
		}
	}
}

// RecordAdminEvent stores an admin event when the realm enables them.
func (s *Service) RecordAdminEvent(ctx context.Context, realm *model.Realm, e *model.AdminEvent) {
	if e.ID == "" {
		e.ID = NewID()
	}
	if e.Time == 0 {
		e.Time = s.Now().UnixMilli()
	}
	e.RealmID = realm.ID
	if !realm.Settings.AdminEventsDetailsEnabled {
		e.Representation = ""
	}
	if realm.Settings.AdminEventsEnabled {
		if err := s.Store.AddAdminEvent(ctx, e); err != nil {
			s.logger().Error("store admin event", "err", err)
		}
	}
	listeners := s.Listeners()
	for _, id := range realm.Settings.EventsListeners {
		if l := listeners[id]; l != nil {
			l.OnAdminEvent(realm, e)
		}
	}
}

// PurgeExpiredEvents applies each realm's eventsExpiration.
func (s *Service) PurgeExpiredEvents(ctx context.Context) error {
	realms, err := s.Store.ListRealms(ctx)
	if err != nil {
		return err
	}
	now := s.Now().UnixMilli()
	for _, r := range realms {
		if exp := r.Settings.EventsExpiration; exp > 0 {
			if err := s.Store.PurgeEvents(ctx, r.ID, now-exp*1000); err != nil {
				return err
			}
		}
	}
	return nil
}
