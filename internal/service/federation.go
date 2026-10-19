package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// UserFederation is a user storage provider (LDAP) behind the local user
// store: users are found and imported from it, it checks their passwords
// and, depending on its edit mode, receives their changes.
type UserFederation interface {
	// LookupUser finds a user that is not imported yet by username or
	// email, and imports it.
	LookupUser(ctx context.Context, realm *model.Realm, ident string) (*model.User, error)
	// ValidateUser refreshes an imported user from its provider; it returns
	// nil when the user no longer exists there.
	ValidateUser(ctx context.Context, realm *model.Realm, u *model.User) (*model.User, error)
	// CheckPassword verifies an imported user's password with the provider.
	CheckPassword(ctx context.Context, realm *model.Realm, u *model.User, password string) (bool, error)
	// PasswordMode tells how a federated user's password is changed.
	PasswordMode(ctx context.Context, realm *model.Realm, u *model.User) (PasswordMode, error)
	// UpdatePassword changes the password in the provider.
	UpdatePassword(ctx context.Context, realm *model.Realm, u *model.User, password string) error
	// UserCreated may register a new local user in a provider.
	UserCreated(ctx context.Context, st *store.Store, realm *model.Realm, u *model.User) error
	// UserUpdated checks and propagates changes of an imported user.
	UserUpdated(ctx context.Context, realm *model.Realm, old, u *model.User) error
	// UserDeleted removes the user from a writable provider.
	UserDeleted(ctx context.Context, realm *model.Realm, u *model.User) error
	// GroupMembership checks and propagates a group join or leave.
	GroupMembership(ctx context.Context, realm *model.Realm, u *model.User, g *model.Group, join bool) error
}

// PasswordMode is how a federated user's password is stored.
type PasswordMode struct {
	Remote         bool // the provider stores it
	ReadOnly       bool // it cannot be changed
	ValidatePolicy bool // check the realm's password policy first
}

type noFederationKey struct{}

// WithoutFederation marks a context in which new users are not registered
// in user storage providers (realm import).
func WithoutFederation(ctx context.Context) context.Context {
	return context.WithValue(ctx, noFederationKey{}, true)
}

func federationDisabled(ctx context.Context) bool { return ctx.Value(noFederationKey{}) != nil }

// ErrReadOnlyUser is returned when a read-only federated user is changed.
var ErrReadOnlyUser = errors.New("user is read only")

// federatedPasswordMode returns the password mode of a user.
func (s *Service) federatedPasswordMode(ctx context.Context, realm *model.Realm, u *model.User) (PasswordMode, error) {
	if s.Federation == nil || u.FederationLink == "" {
		return PasswordMode{ValidatePolicy: true}, nil
	}
	return s.Federation.PasswordMode(ctx, realm, u)
}

// DeleteUser deletes a user, from a writable provider too.
func (s *Service) DeleteUser(ctx context.Context, realm *model.Realm, u *model.User) error {
	if s.Federation != nil && u.FederationLink != "" {
		if err := s.Federation.UserDeleted(ctx, realm, u); err != nil {
			return err
		}
	}
	return s.Store.DeleteUser(ctx, realm.ID, u.ID)
}

// JoinGroup adds a user to a group, checking group mappers of providers.
func (s *Service) JoinGroup(ctx context.Context, realm *model.Realm, u *model.User, g *model.Group) error {
	if s.Federation != nil {
		if err := s.Federation.GroupMembership(ctx, realm, u, g, true); err != nil {
			return err
		}
	}
	return s.Store.AddUserToGroup(ctx, u.ID, g.ID)
}

// LeaveGroup removes a user from a group, checking group mappers of providers.
func (s *Service) LeaveGroup(ctx context.Context, realm *model.Realm, u *model.User, g *model.Group) error {
	if s.Federation != nil {
		if err := s.Federation.GroupMembership(ctx, realm, u, g, false); err != nil {
			return err
		}
	}
	return s.Store.RemoveUserFromGroup(ctx, u.ID, g.ID)
}
