package auth

import "context"

type contextKey struct{}

// WithUser attaches the authenticated user to ctx.
func WithUser(ctx context.Context, user User) context.Context {
	return context.WithValue(ctx, contextKey{}, user)
}

// CurrentUser returns the user stored by WithUser.
func CurrentUser(ctx context.Context) (User, bool) {
	user, ok := ctx.Value(contextKey{}).(User)
	return user, ok
}
