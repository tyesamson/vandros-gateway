package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/tyesamson/vandros-gateway/config"
	"github.com/tyesamson/vandros-gateway/internal/relpath"
)

// Session is an active login, without the cookie token.
type Session struct {
	UserID   int64
	Username string
	Expires  time.Time
}

// ListUsers returns every account and its scopes.
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	users := make([]User, 0, len(ids))
	for _, id := range ids {
		user, err := s.userByID(ctx, id)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// SetPassword replaces an account password.
func (s *Store) SetPassword(ctx context.Context, userID int64, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ?`, hash, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("user not found")
	}
	return nil
}

// SetRole changes an account between admin and client.
// The last administrator cannot be demoted.
func (s *Store) SetRole(ctx context.Context, userID int64, role string) (bool, error) {
	if role != RoleAdmin && role != RoleClient {
		return false, errors.New("invalid role")
	}
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return false, err
	}
	if user.Role == role {
		return false, nil
	}
	if user.Role == RoleAdmin && role == RoleClient {
		if err := s.keepAnAdmin(ctx, userID); err != nil {
			return false, err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID); err != nil {
		return false, err
	}
	if role == RoleAdmin {
		if _, err := tx.ExecContext(ctx, `DELETE FROM scopes WHERE user_id = ?`, userID); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteUser removes an account. You cannot delete yourself or the last administrator.
func (s *Store) DeleteUser(ctx context.Context, actorID, userID int64) error {
	if actorID == userID {
		return errors.New("you cannot delete your own account")
	}
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Role == RoleAdmin {
		if err := s.keepAnAdmin(ctx, userID); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

// AddScope grants a client access to a directory.
func (s *Store) AddScope(ctx context.Context, userID int64, scope Scope) error {
	user, err := s.userByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.Role != RoleClient {
		return errors.New("administrators already have every mount")
	}
	if !config.ValidMountID(scope.MountID) {
		return fmt.Errorf("invalid mount id %q", scope.MountID)
	}
	cleaned, err := relpath.Clean(scope.Path)
	if err != nil {
		return fmt.Errorf("scope path: %w", err)
	}
	if !scope.Read && !scope.Write && !scope.Delete {
		return errors.New("a scope needs a permission")
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO scopes(user_id, mount_id, path, can_read, can_write, can_delete) VALUES (?, ?, ?, ?, ?, ?)`,
		userID, scope.MountID, cleaned, boolInt(scope.Read), boolInt(scope.Write), boolInt(scope.Delete))
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return errors.New("that scope already exists")
	}
	return err
}

// DeleteScope removes one scope row owned by userID.
func (s *Store) DeleteScope(ctx context.Context, userID, scopeID int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM scopes WHERE id = ? AND user_id = ?`, scopeID, userID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("scope not found")
	}
	return nil
}

// Sessions lists logins that have not expired.
func (s *Store) Sessions(ctx context.Context) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT u.id, u.username, s.expires_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.expires_at > ?
ORDER BY u.username, s.expires_at`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var item Session
		var exp int64
		if err := rows.Scan(&item.UserID, &item.Username, &exp); err != nil {
			return nil, err
		}
		item.Expires = time.Unix(exp, 0)
		out = append(out, item)
	}
	return out, rows.Err()
}

// RevokeSessions signs a user out of every browser.
func (s *Store) RevokeSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// EnsureBranding stores the display name the first time the database is used.
func (s *Store) EnsureBranding(ctx context.Context, name string) error {
	_, ok, err := s.Setting(ctx, "brand_name")
	if err != nil || ok {
		return err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Vandros Gateway"
	}
	return s.SetSetting(ctx, "brand_name", name)
}

// Setting reads one settings row.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var value string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return value, true, nil
}

// SetSetting inserts or replaces one settings row.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO settings(key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// ClearSetting removes one settings row.
func (s *Store) ClearSetting(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM settings WHERE key = ?`, key)
	return err
}

func (s *Store) keepAnAdmin(ctx context.Context, exceptID int64) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users WHERE role = ? AND id != ?`, RoleAdmin, exceptID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return errors.New("the last administrator cannot be removed")
	}
	return nil
}
