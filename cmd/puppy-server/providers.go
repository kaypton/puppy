package main

import (
	"sync/atomic"

	"github.com/puppy/pkg/dashboard"
	frontendhttpproxy "github.com/puppy/pkg/httpproxy"
	frontendsocksproxy "github.com/puppy/pkg/socksproxy"
	frontendtunproxy "github.com/puppy/pkg/tunproxy"
)

// configProvider implements dashboard.ConfigProvider by returning a sanitized
// view of the loaded configuration with passwords and secrets redacted.
type configProvider struct {
	config atomic.Pointer[configuration]
}

func (p *configProvider) Update(cfg *configuration) {
	p.config.Store(cfg)
}

func (p *configProvider) SanitizedConfig() any {
	config := p.config.Load()
	frontends := make(map[string]any, len(config.Frontends))
	for name, group := range config.Frontends {
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

	backends := make(map[string]any, len(config.Backends))
	for name, group := range config.Backends {
		backends[name] = map[string]any{"type": group.Type}
	}

	shims := make(map[string]any, len(config.Shims))
	for name, sc := range config.Shims {
		shims[name] = map[string]any{"buffer_size": sc.BufferSize}
	}

	result := map[string]any{
		"frontend":  config.Frontend,
		"frontends": frontends,
		"backends":  backends,
		"shims":     shims,
	}
	if config.Dashboard != nil {
		result["dashboard"] = map[string]any{
			"enabled":        config.Dashboard.Enabled,
			"listen_address": config.Dashboard.ListenAddress,
			"listen_port":    config.Dashboard.ListenPort,
			"tls":            config.Dashboard.TLSCertFile != "",
			"auth":           config.Dashboard.Token != "",
		}
	}
	return result
}

// frontendProvider implements dashboard.FrontendProvider.
type frontendProvider struct {
	config atomic.Pointer[configuration]
}

func (p *frontendProvider) Update(cfg *configuration) {
	p.config.Store(cfg)
}

func (p *frontendProvider) Frontends() []dashboard.FrontendInfo {
	config := p.config.Load()
	result := make([]dashboard.FrontendInfo, 0, len(config.Frontends))
	for name, group := range config.Frontends {
		result = append(result, dashboard.FrontendInfo{
			Name: name,
			Type: group.Type,
		})
	}
	return result
}

// backendProvider implements dashboard.BackendProvider.
type backendProvider struct {
	config atomic.Pointer[configuration]
}

func (p *backendProvider) Update(cfg *configuration) {
	p.config.Store(cfg)
}

func (p *backendProvider) Backends() []dashboard.BackendInfo {
	config := p.config.Load()
	result := make([]dashboard.BackendInfo, 0, len(config.Backends))
	for name, group := range config.Backends {
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
