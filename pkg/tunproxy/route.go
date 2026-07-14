package tunproxy

// routeManager captures the platform-specific route configuration lifecycle.
// Apply redirects the default route through the TUN device; Restore reverses
// the changes. Implementations must be safe to call Restore multiple times.
type routeManager interface {
	Apply() error
	Restore() error
}

// noOpRouteManager is used when auto_route is disabled.
type noOpRouteManager struct{}

func (noOpRouteManager) Apply() error   { return nil }
func (noOpRouteManager) Restore() error { return nil }
