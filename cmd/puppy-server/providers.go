package main

import (
	"sync"

	"github.com/puppy/pkg/dashboard"
	frontendhttpproxy "github.com/puppy/pkg/httpproxy"
	frontendsocksproxy "github.com/puppy/pkg/socksproxy"
	frontendtunproxy "github.com/puppy/pkg/tunproxy"
)

// configProvider implements dashboard.ConfigProvider by returning a sanitized
// view of the loaded configuration with passwords and secrets redacted.
type configProvider struct {
	config *configuration
}

func (p *configProvider) SanitizedConfig() any {
	frontends := make(map[string]any, len(p.config.Frontends))
	for name, group := range p.config.Frontends {
		entry := map[string]any{"type": group.Type}
		switch fc := group.Configuration.(type) {
		case frontendhttpproxy.Configuration:
			entry["listen_address"] = fc.ListenAddress
			entry["listen_port"] = fc.ListenPort
			entry["tls"] = fc.TLSCertFile != ""
			entry["auth"] = fc.Username != ""
			entry["camouflage"] = fc.Camouflage
			entry["backend"] = fc.Backend
		case frontendsocksproxy.Configuration:
			entry["listen_address"] = fc.ListenAddress
			entry["listen_port"] = fc.ListenPort
			entry["tls"] = fc.TLSCertFile != ""
			entry["auth"] = fc.Username != ""
			entry["backend"] = fc.Backend
		case frontendtunproxy.Configuration:
			entry["device_name"] = fc.DeviceName
			entry["backends"] = fc.BackendReferences()
			if fc.Fallback != "" {
				entry["fallback"] = fc.Fallback
			}
		}
		frontends[name] = entry
	}

	backends := make(map[string]any, len(p.config.Backends))
	for name, group := range p.config.Backends {
		backends[name] = map[string]any{"type": group.Type}
	}

	shims := make(map[string]any, len(p.config.Shims))
	for name, sc := range p.config.Shims {
		shims[name] = map[string]any{"buffer_size": sc.BufferSize}
	}

	result := map[string]any{
		"frontend":  p.config.Frontend,
		"frontends": frontends,
		"backends":  backends,
		"shims":     shims,
	}
	if p.config.Dashboard != nil {
		result["dashboard"] = map[string]any{
			"enabled":        p.config.Dashboard.Enabled,
			"listen_address": p.config.Dashboard.ListenAddress,
			"listen_port":    p.config.Dashboard.ListenPort,
			"tls":            p.config.Dashboard.TLSCertFile != "",
			"auth":           p.config.Dashboard.Token != "",
		}
	}
	return result
}

// frontendProvider implements dashboard.FrontendProvider.
type frontendProvider struct {
	config   *configuration
	statuses map[string]string
	mu       sync.RWMutex
}

func (p *frontendProvider) Frontends() []dashboard.FrontendInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]dashboard.FrontendInfo, 0, len(p.config.Frontends))
	for name, group := range p.config.Frontends {
		status := p.statuses[name]
		if status == "" {
			status = "stopped"
		}
		result = append(result, dashboard.FrontendInfo{
			Name:   name,
			Type:   group.Type,
			Status: status,
		})
	}
	return result
}

// setStatus updates the status of a frontend.
func (p *frontendProvider) setStatus(name, status string) {
	p.mu.Lock()
	p.statuses[name] = status
	p.mu.Unlock()
}

// backendProvider implements dashboard.BackendProvider.
type backendProvider struct {
	config *configuration
}

func (p *backendProvider) Backends() []dashboard.BackendInfo {
	result := make([]dashboard.BackendInfo, 0, len(p.config.Backends))
	for name, group := range p.config.Backends {
		result = append(result, dashboard.BackendInfo{
			Name:         name,
			Type:         group.Type,
			Capabilities: backendCapabilities(group),
		})
	}
	return result
}

// backendCapabilities returns the capability list for a backend group inferred
// from its type, avoiding the side effects of constructing the actual backend.
func backendCapabilities(group backendGroup) []dashboard.CapabilityInfo {
	switch group.Type {
	case "direct":
		return []dashboard.CapabilityInfo{
			{Network: "tcp", Protocol: "*"},
			{Network: "udp", Protocol: "*"},
		}
	case "httpproxy", "socksproxy":
		return []dashboard.CapabilityInfo{
			{Network: "tcp", Protocol: "*"},
		}
	default:
		return nil
	}
}
