// Package common defines shared types and interfaces used across puppy's
// frontend and adapter packages. The primary abstraction is the Backend
// interface, implemented by pkg/adapter/* (direct, httpproxy, socksproxy, ...)
// and consumed by pkg/httpproxy (and future frontends).
package common
