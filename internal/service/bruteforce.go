package service

import (
	"context"
	"errors"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// LockStatus is the brute force state of a user (the
// /attack-detection/brute-force/users/{id} response).
type LockStatus struct {
	NumFailures          int    `json:"numFailures"`
	NumTemporaryLockouts int    `json:"numTemporaryLockouts"`
	Disabled             bool   `json:"disabled"`
	LastIPFailure        string `json:"lastIPFailure"`
	LastFailure          int64  `json:"lastFailure"`
	FailedLoginNotBefore int64  `json:"failedLoginNotBefore"`
}

// LockStatus returns the brute force state of a user.
func (s *Service) LockStatus(ctx context.Context, realm *model.Realm, userID string) (LockStatus, error) {
	var st LockStatus
	if !realm.Settings.BruteForceProtected {
		return st, nil
	}
	f, err := s.Store.GetLoginFailure(ctx, realm.ID, userID)
	if errors.Is(err, store.ErrNotFound) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st = LockStatus{NumFailures: f.NumFailures, NumTemporaryLockouts: f.NumTemporaryLockouts, LastIPFailure: f.LastIP,
		LastFailure: f.LastFailure, FailedLoginNotBefore: f.FailedLoginNotBefore}
	st.Disabled = f.FailedLoginNotBefore > s.Now().Unix()
	return st, nil
}

// TemporarilyLocked reports whether brute force detection currently blocks
// logins of the user. While locked, even correct passwords are rejected.
func (s *Service) TemporarilyLocked(ctx context.Context, realm *model.Realm, u *model.User) (bool, error) {
	st, err := s.LockStatus(ctx, realm, u.ID)
	return st.Disabled, err
}

// LoginFailed records a failed password check, following the default
// brute force protector: failures reset after maxDeltaTimeSeconds,
// quick successive failures wait minimumQuickLoginWaitSeconds, and every
// failureFactor failures (MULTIPLE) or every failure past it (LINEAR) add
// waitIncrementSeconds, up to maxFailureWaitSeconds. With permanentLockout
// the user is disabled once the limit is reached.
func (s *Service) LoginFailed(ctx context.Context, realm *model.Realm, u *model.User, ip string) error {
	cfg := realm.Settings
	if !cfg.BruteForceProtected {
		return nil
	}
	now := s.Now()
	f, err := s.Store.GetLoginFailure(ctx, realm.ID, u.ID)
	if errors.Is(err, store.ErrNotFound) {
		f, err = &model.LoginFailure{RealmID: realm.ID, UserID: u.ID}, nil
	}
	if err != nil {
		return err
	}
	if f.FailedLoginNotBefore > now.Unix() {
		return nil // already locked: failures are not counted
	}
	previous := f.LastFailure
	if previous > 0 && now.UnixMilli()-previous > int64(cfg.MaxDeltaTimeSeconds)*1000 {
		f.NumFailures = 0
	}
	f.NumFailures++
	f.LastFailure = now.UnixMilli()
	f.LastIP = ip

	permanentOnly := cfg.PermanentLockout && cfg.MaxTemporaryLockouts == 0
	wait := 0
	if !permanentOnly {
		if previous > 0 && now.UnixMilli()-previous < cfg.QuickLoginCheckMilliSeconds {
			wait = cfg.MinimumQuickLoginWaitSeconds
		}
		factor := cfg.FailureFactor
		if factor <= 0 {
			factor = 30
		}
		var faults int
		if cfg.BruteForceStrategy == "LINEAR" {
			if f.NumFailures >= factor {
				faults = f.NumFailures - factor + 1
			}
		} else if f.NumFailures%factor == 0 {
			faults = f.NumFailures / factor
		}
		if inc := cfg.WaitIncrementSeconds * faults; inc > wait {
			wait = inc
		}
		if cfg.MaxFailureWaitSeconds > 0 && wait > cfg.MaxFailureWaitSeconds {
			wait = cfg.MaxFailureWaitSeconds
		}
	}
	if wait > 0 {
		f.FailedLoginNotBefore = now.Unix() + int64(wait)
		f.NumTemporaryLockouts++
		s.RecordEvent(ctx, realm, &model.Event{Type: "USER_DISABLED_BY_TEMPORARY_LOCKOUT", UserID: u.ID, IPAddress: ip})
	}
	if err := s.Store.SaveLoginFailure(ctx, f); err != nil {
		return err
	}
	if cfg.PermanentLockout && ((permanentOnly && f.NumFailures >= cfg.FailureFactor) ||
		(cfg.MaxTemporaryLockouts > 0 && f.NumTemporaryLockouts > cfg.MaxTemporaryLockouts)) {
		u.Enabled = false
		if u.Attributes == nil {
			u.Attributes = map[string][]string{}
		}
		u.Attributes["disabledReason"] = []string{"permanentLockout"}
		if err := s.Store.UpdateUser(ctx, u); err != nil {
			return err
		}
		s.RecordEvent(ctx, realm, &model.Event{Type: "USER_DISABLED_BY_PERMANENT_LOCKOUT", UserID: u.ID, IPAddress: ip})
	}
	return nil
}

// LoginSucceeded clears the user's failure counter.
func (s *Service) LoginSucceeded(ctx context.Context, realm *model.Realm, u *model.User) error {
	if !realm.Settings.BruteForceProtected {
		return nil
	}
	return s.Store.DeleteLoginFailure(ctx, realm.ID, u.ID)
}
