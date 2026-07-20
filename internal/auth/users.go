package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"secureshare/internal/config"
)

const (
	RoleAdmin     = "admin"
	RoleDeveloper = "developer"
	RoleViewer    = "viewer"

	StatusActive   = "active"
	StatusDisabled = "disabled"
)

var ErrInvalidCredentials = errors.New("invalid credentials")

type User struct {
	ID                  uuid.UUID  `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email"`
	Role                string     `json:"role"`
	Status              string     `json:"status"`
	ForcePasswordChange bool       `json:"force_password_change"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	PasswordChangedAt   *time.Time `json:"password_changed_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type UserWithPassword struct {
	User
	PasswordHash string
}

type SessionInfo struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastSeenAt time.Time  `json:"last_seen_at"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	Current    bool       `json:"current"`
}

type UserCreate struct {
	Username            string
	Email               string
	Password            string
	Role                string
	Status              string
	ForcePasswordChange bool
}

type UserPatch struct {
	Username            *string
	Email               *string
	Role                *string
	Status              *string
	ForcePasswordChange *bool
}

type UserStore interface {
	CountUsers(context.Context) (int, error)
	CreateUser(context.Context, UserCreate) (User, error)
	UserForLogin(context.Context, string) (UserWithPassword, error)
	UserByID(context.Context, uuid.UUID) (User, error)
	ListUsers(context.Context) ([]User, error)
	UpdateUser(context.Context, uuid.UUID, UserPatch) (User, error)
	SetUserStatus(context.Context, uuid.UUID, string) (User, error)
	SetPassword(context.Context, uuid.UUID, string, bool) error
	TouchLastLogin(context.Context, uuid.UUID) error
	CreateSession(context.Context, uuid.UUID, []byte, time.Time, time.Time) (uuid.UUID, error)
	SessionByHash(context.Context, []byte, time.Time, time.Duration) (User, uuid.UUID, time.Time, time.Time, error)
	RevokeSession(context.Context, []byte) error
	RevokeOtherSessions(context.Context, uuid.UUID, []byte) error
	ListSessions(context.Context, uuid.UUID, []byte) ([]SessionInfo, error)
}

type Repository struct {
	db *pgxpool.Pool
}

func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

func PermissionsForRole(role string) []string {
	switch role {
	case RoleAdmin:
		return []string{
			"dashboard:read",
			"system:read",
			"secret:create",
			"secret:read-metadata",
			"secret:revoke",
			"user:manage",
			"api-client:manage",
			"email-settings:manage",
			"email:send",
			"system:cleanup",
			"api-docs:read",
			"account:manage",
		}
	case RoleDeveloper:
		return []string{
			"dashboard:read",
			"secret:create",
			"secret:read-metadata",
			"secret:revoke",
			"email:send",
			"api-docs:read",
			"account:manage",
		}
	case RoleViewer:
		return []string{
			"dashboard:read",
			"system:read",
			"secret:read-metadata",
			"api-docs:read",
			"account:manage",
		}
	default:
		return nil
	}
}

func ValidRole(role string) bool {
	return role == RoleAdmin || role == RoleDeveloper || role == RoleViewer
}

func ValidStatus(status string) bool {
	return status == StatusActive || status == StatusDisabled
}

func ValidateUserPassword(password string, production bool) error {
	trimmed := strings.TrimSpace(password)
	if trimmed == "" {
		return errors.New("password is required")
	}
	if production && len([]rune(trimmed)) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	if production {
		switch strings.ToLower(trimmed) {
		case "change-me", "change-me-now", "password", "password123", "admin", "admin123", "secureshare":
			return errors.New("password is a common default")
		}
	}
	return nil
}

func NormalizeLogin(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func GenerateToken(bytes int) (string, error) {
	raw := make([]byte, bytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func BootstrapAdmin(ctx context.Context, store UserStore, cfg config.Config) error {
	count, err := store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if strings.TrimSpace(cfg.BootstrapAdminUsername) == "" && strings.TrimSpace(cfg.BootstrapAdminPassword) == "" {
		return nil
	}
	if err := ValidateUserPassword(cfg.BootstrapAdminPassword, cfg.AppEnv != "development"); err != nil {
		return fmt.Errorf("bootstrap admin password rejected: %w", err)
	}
	_, err = store.CreateUser(ctx, UserCreate{
		Username:            cfg.BootstrapAdminUsername,
		Email:               cfg.BootstrapAdminEmail,
		Password:            cfg.BootstrapAdminPassword,
		Role:                RoleAdmin,
		Status:              StatusActive,
		ForcePasswordChange: cfg.AppEnv != "development",
	})
	return err
}

func (r *Repository) CountUsers(ctx context.Context) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

func (r *Repository) CreateUser(ctx context.Context, params UserCreate) (User, error) {
	params = normalizeUserCreate(params)
	if err := validateUserCreate(params, false); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(params.Password)
	if err != nil {
		return User{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := uuid.NewRandom()
	if err != nil {
		return User{}, err
	}
	var user User
	err = r.db.QueryRow(ctx, `
		INSERT INTO users (id, username, email, password_hash, role, status, force_password_change, password_changed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
		RETURNING id, username, email, role, status, force_password_change,
			last_login_at, password_changed_at, created_at, updated_at
	`, id, params.Username, params.Email, hash, params.Role, params.Status, params.ForcePasswordChange).Scan(
		&user.ID, &user.Username, &user.Email, &user.Role, &user.Status, &user.ForcePasswordChange,
		&user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt,
	)
	return user, err
}

func (r *Repository) UserForLogin(ctx context.Context, login string) (UserWithPassword, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	login = NormalizeLogin(login)
	var user UserWithPassword
	err := r.db.QueryRow(ctx, `
		SELECT id, username, email, password_hash, role, status, force_password_change,
			last_login_at, password_changed_at, created_at, updated_at
		FROM users
		WHERE lower(username) = $1 OR lower(email) = $1
	`, login).Scan(&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.Role, &user.Status,
		&user.ForcePasswordChange, &user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return UserWithPassword{}, ErrInvalidCredentials
	}
	return user, err
}

func (r *Repository) UserByID(ctx context.Context, id uuid.UUID) (User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user User
	err := r.db.QueryRow(ctx, `
		SELECT id, username, email, role, status, force_password_change,
			last_login_at, password_changed_at, created_at, updated_at
		FROM users WHERE id = $1
	`, id).Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.Status, &user.ForcePasswordChange,
		&user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func (r *Repository) ListUsers(ctx context.Context) ([]User, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `
		SELECT id, username, email, role, status, force_password_change,
			last_login_at, password_changed_at, created_at, updated_at
		FROM users ORDER BY created_at DESC, username ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Email, &user.Role, &user.Status,
			&user.ForcePasswordChange, &user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (r *Repository) UpdateUser(ctx context.Context, id uuid.UUID, patch UserPatch) (User, error) {
	current, err := r.UserByID(ctx, id)
	if err != nil {
		return User{}, err
	}
	username := current.Username
	email := current.Email
	role := current.Role
	status := current.Status
	force := current.ForcePasswordChange
	if patch.Username != nil {
		username = strings.TrimSpace(*patch.Username)
	}
	if patch.Email != nil {
		email = strings.TrimSpace(strings.ToLower(*patch.Email))
	}
	if patch.Role != nil {
		role = strings.TrimSpace(*patch.Role)
	}
	if patch.Status != nil {
		status = strings.TrimSpace(*patch.Status)
	}
	if patch.ForcePasswordChange != nil {
		force = *patch.ForcePasswordChange
	}
	if !ValidRole(role) || !ValidStatus(status) || username == "" || email == "" {
		return User{}, errors.New("invalid user update")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var user User
	err = r.db.QueryRow(ctx, `
		UPDATE users
		SET username = $2, email = $3, role = $4, status = $5, force_password_change = $6
		WHERE id = $1
		RETURNING id, username, email, role, status, force_password_change,
			last_login_at, password_changed_at, created_at, updated_at
	`, id, username, email, role, status, force).Scan(&user.ID, &user.Username, &user.Email, &user.Role,
		&user.Status, &user.ForcePasswordChange, &user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt)
	return user, err
}

func (r *Repository) SetUserStatus(ctx context.Context, id uuid.UUID, status string) (User, error) {
	return r.UpdateUser(ctx, id, UserPatch{Status: &status})
}

func (r *Repository) SetPassword(ctx context.Context, id uuid.UUID, password string, forceChange bool) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err = r.db.Exec(ctx, `
		UPDATE users
		SET password_hash = $2,
			password_changed_at = NOW(),
			force_password_change = $3
		WHERE id = $1
	`, id, hash, forceChange)
	return err
}

func (r *Repository) TouchLastLogin(ctx context.Context, id uuid.UUID) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `UPDATE users SET last_login_at = NOW() WHERE id = $1`, id)
	return err
}

func (r *Repository) CreateSession(ctx context.Context, userID uuid.UUID, tokenHash []byte, expiresAt, now time.Time) (uuid.UUID, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	id, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, err
	}
	_, err = r.db.Exec(ctx, `
		INSERT INTO user_sessions (id, user_id, session_token_hash, expires_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5)
	`, id, userID, tokenHash, expiresAt, now)
	return id, err
}

func (r *Repository) SessionByHash(ctx context.Context, tokenHash []byte, now time.Time, idleTimeout time.Duration) (User, uuid.UUID, time.Time, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	idleSeconds := int64(idleTimeout.Seconds())
	if idleSeconds <= 0 {
		idleSeconds = int64((24 * time.Hour * 365).Seconds())
	}
	var user User
	var sessionID uuid.UUID
	var expiresAt time.Time
	var lastSeenAt time.Time
	err := r.db.QueryRow(ctx, `
		UPDATE user_sessions
		SET last_seen_at = $2
		FROM users
		WHERE user_sessions.user_id = users.id
		  AND user_sessions.session_token_hash = $1
		  AND user_sessions.revoked_at IS NULL
		  AND user_sessions.expires_at > $2
		  AND user_sessions.last_seen_at > $2 - make_interval(secs => $3)
		  AND users.status = 'active'
		RETURNING user_sessions.id, user_sessions.expires_at, user_sessions.last_seen_at,
			users.id, users.username, users.email, users.role, users.status, users.force_password_change,
			users.last_login_at, users.password_changed_at, users.created_at, users.updated_at
	`, tokenHash, now, idleSeconds).Scan(&sessionID, &expiresAt, &lastSeenAt, &user.ID, &user.Username, &user.Email,
		&user.Role, &user.Status, &user.ForcePasswordChange, &user.LastLoginAt, &user.PasswordChangedAt, &user.CreatedAt, &user.UpdatedAt)
	return user, sessionID, expiresAt, lastSeenAt, err
}

func (r *Repository) RevokeSession(ctx context.Context, tokenHash []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `UPDATE user_sessions SET revoked_at = NOW() WHERE session_token_hash = $1 AND revoked_at IS NULL`, tokenHash)
	return err
}

func (r *Repository) RevokeOtherSessions(ctx context.Context, userID uuid.UUID, currentHash []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := r.db.Exec(ctx, `
		UPDATE user_sessions
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL AND session_token_hash <> $2
	`, userID, currentHash)
	return err
}

func (r *Repository) ListSessions(ctx context.Context, userID uuid.UUID, currentHash []byte) ([]SessionInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rows, err := r.db.Query(ctx, `
		SELECT id, user_id, expires_at, last_seen_at, created_at, revoked_at,
			CASE WHEN session_token_hash = $2 THEN TRUE ELSE FALSE END
		FROM user_sessions
		WHERE user_id = $1
		ORDER BY created_at DESC
	`, userID, currentHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []SessionInfo
	for rows.Next() {
		var session SessionInfo
		if err := rows.Scan(&session.ID, &session.UserID, &session.ExpiresAt, &session.LastSeenAt,
			&session.CreatedAt, &session.RevokedAt, &session.Current); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func Authenticate(ctx context.Context, store UserStore, login, password string) (User, bool, error) {
	record, err := store.UserForLogin(ctx, login)
	if errors.Is(err, ErrInvalidCredentials) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	if record.Status != StatusActive || !VerifyPassword(password, record.PasswordHash) {
		return User{}, false, nil
	}
	return record.User, true, nil
}

type MemoryStore struct {
	mu       sync.Mutex
	users    map[uuid.UUID]UserWithPassword
	sessions map[string]memorySession
	clients  map[uuid.UUID]APIClientWithSecret
}

type memorySession struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Hash       []byte
	ExpiresAt  time.Time
	LastSeenAt time.Time
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{users: map[uuid.UUID]UserWithPassword{}, sessions: map[string]memorySession{}, clients: map[uuid.UUID]APIClientWithSecret{}}
}

func (m *MemoryStore) CountUsers(context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users), nil
}

func (m *MemoryStore) CreateUser(_ context.Context, params UserCreate) (User, error) {
	params = normalizeUserCreate(params)
	if err := validateUserCreate(params, false); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(params.Password)
	if err != nil {
		return User{}, err
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	user := UserWithPassword{
		User: User{
			ID:                  id,
			Username:            params.Username,
			Email:               params.Email,
			Role:                params.Role,
			Status:              params.Status,
			ForcePasswordChange: params.ForcePasswordChange,
			CreatedAt:           now,
			UpdatedAt:           now,
			PasswordChangedAt:   &now,
		},
		PasswordHash: hash,
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.users {
		if strings.EqualFold(existing.Username, user.Username) || strings.EqualFold(existing.Email, user.Email) {
			return User{}, errors.New("user already exists")
		}
	}
	m.users[id] = user
	return user.User, nil
}

func (m *MemoryStore) UserForLogin(_ context.Context, login string) (UserWithPassword, error) {
	login = NormalizeLogin(login)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, user := range m.users {
		if NormalizeLogin(user.Username) == login || NormalizeLogin(user.Email) == login {
			return user, nil
		}
	}
	return UserWithPassword{}, ErrInvalidCredentials
}

func (m *MemoryStore) UserByID(_ context.Context, id uuid.UUID) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	user, ok := m.users[id]
	if !ok {
		return User{}, pgx.ErrNoRows
	}
	return user.User, nil
}

func (m *MemoryStore) ListUsers(context.Context) ([]User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	users := make([]User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user.User)
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Username < users[j].Username })
	return users, nil
}

func (m *MemoryStore) UpdateUser(ctx context.Context, id uuid.UUID, patch UserPatch) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.users[id]
	if !ok {
		return User{}, pgx.ErrNoRows
	}
	if patch.Username != nil {
		record.Username = strings.TrimSpace(*patch.Username)
	}
	if patch.Email != nil {
		record.Email = strings.TrimSpace(strings.ToLower(*patch.Email))
	}
	if patch.Role != nil {
		record.Role = strings.TrimSpace(*patch.Role)
	}
	if patch.Status != nil {
		record.Status = strings.TrimSpace(*patch.Status)
	}
	if patch.ForcePasswordChange != nil {
		record.ForcePasswordChange = *patch.ForcePasswordChange
	}
	if !ValidRole(record.Role) || !ValidStatus(record.Status) || record.Username == "" || record.Email == "" {
		return User{}, errors.New("invalid user update")
	}
	record.UpdatedAt = time.Now().UTC()
	m.users[id] = record
	return record.User, nil
}

func (m *MemoryStore) SetUserStatus(ctx context.Context, id uuid.UUID, status string) (User, error) {
	return m.UpdateUser(ctx, id, UserPatch{Status: &status})
}

func (m *MemoryStore) SetPassword(_ context.Context, id uuid.UUID, password string, forceChange bool) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.users[id]
	if !ok {
		return pgx.ErrNoRows
	}
	record.PasswordHash = hash
	record.PasswordChangedAt = &now
	record.ForcePasswordChange = forceChange
	record.UpdatedAt = now
	m.users[id] = record
	return nil
}

func (m *MemoryStore) TouchLastLogin(_ context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	record, ok := m.users[id]
	if !ok {
		return pgx.ErrNoRows
	}
	record.LastLoginAt = &now
	record.UpdatedAt = now
	m.users[id] = record
	return nil
}

func (m *MemoryStore) CreateSession(_ context.Context, userID uuid.UUID, tokenHash []byte, expiresAt, now time.Time) (uuid.UUID, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return uuid.Nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[string(tokenHash)] = memorySession{ID: id, UserID: userID, Hash: append([]byte(nil), tokenHash...), ExpiresAt: expiresAt, LastSeenAt: now, CreatedAt: now}
	return id, nil
}

func (m *MemoryStore) SessionByHash(_ context.Context, tokenHash []byte, now time.Time, idleTimeout time.Duration) (User, uuid.UUID, time.Time, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[string(tokenHash)]
	if !ok || session.RevokedAt != nil || now.After(session.ExpiresAt) || (idleTimeout > 0 && now.Sub(session.LastSeenAt) > idleTimeout) {
		return User{}, uuid.Nil, time.Time{}, time.Time{}, pgx.ErrNoRows
	}
	record, ok := m.users[session.UserID]
	if !ok || record.Status != StatusActive {
		return User{}, uuid.Nil, time.Time{}, time.Time{}, pgx.ErrNoRows
	}
	session.LastSeenAt = now
	m.sessions[string(tokenHash)] = session
	return record.User, session.ID, session.ExpiresAt, session.LastSeenAt, nil
}

func (m *MemoryStore) RevokeSession(_ context.Context, tokenHash []byte) error {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[string(tokenHash)]
	if ok && session.RevokedAt == nil {
		session.RevokedAt = &now
		m.sessions[string(tokenHash)] = session
	}
	return nil
}

func (m *MemoryStore) RevokeOtherSessions(_ context.Context, userID uuid.UUID, currentHash []byte) error {
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, session := range m.sessions {
		if session.UserID == userID && subtle.ConstantTimeCompare(session.Hash, currentHash) != 1 && session.RevokedAt == nil {
			session.RevokedAt = &now
			m.sessions[key] = session
		}
	}
	return nil
}

func (m *MemoryStore) ListSessions(_ context.Context, userID uuid.UUID, currentHash []byte) ([]SessionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var sessions []SessionInfo
	for _, session := range m.sessions {
		if session.UserID != userID {
			continue
		}
		sessions = append(sessions, SessionInfo{
			ID:         session.ID,
			UserID:     session.UserID,
			ExpiresAt:  session.ExpiresAt,
			LastSeenAt: session.LastSeenAt,
			CreatedAt:  session.CreatedAt,
			RevokedAt:  session.RevokedAt,
			Current:    subtle.ConstantTimeCompare(session.Hash, currentHash) == 1,
		})
	}
	return sessions, nil
}

func normalizeUserCreate(params UserCreate) UserCreate {
	params.Username = strings.TrimSpace(params.Username)
	params.Email = strings.TrimSpace(strings.ToLower(params.Email))
	params.Role = strings.TrimSpace(params.Role)
	if params.Role == "" {
		params.Role = RoleDeveloper
	}
	params.Status = strings.TrimSpace(params.Status)
	if params.Status == "" {
		params.Status = StatusActive
	}
	return params
}

func validateUserCreate(params UserCreate, production bool) error {
	if params.Username == "" || len(params.Username) > 100 || strings.ContainsAny(params.Username, " \t\r\n") {
		return errors.New("invalid username")
	}
	if params.Email == "" || len(params.Email) > 255 || !strings.Contains(params.Email, "@") {
		return errors.New("invalid email")
	}
	if !ValidRole(params.Role) {
		return errors.New("invalid role")
	}
	if !ValidStatus(params.Status) {
		return errors.New("invalid status")
	}
	return ValidateUserPassword(params.Password, production)
}
