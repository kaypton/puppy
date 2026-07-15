//go:build linux

package tunproxy

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigureLinuxSocket_BindsAndMarks(t *testing.T) {
	var calls []string
	err := configureLinuxSocket(42, "eth0", func(fd int, iface string) error {
		calls = append(calls, "bind")
		if fd != 42 || iface != "eth0" {
			t.Fatalf("bind = (%d, %q), want (42, eth0)", fd, iface)
		}
		return nil
	}, func(fd, mark int) error {
		calls = append(calls, "mark")
		if fd != 42 || mark != linuxBypassMark {
			t.Fatalf("mark = (%d, %#x), want (42, %#x)", fd, mark, linuxBypassMark)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("configureLinuxSocket: %v", err)
	}
	if strings.Join(calls, ",") != "bind,mark" {
		t.Fatalf("calls = %v, want [bind mark]", calls)
	}
}

func TestConfigureLinuxSocket_StopsAfterBindFailure(t *testing.T) {
	marked := false
	err := configureLinuxSocket(42, "eth0", func(int, string) error {
		return errors.New("bind failed")
	}, func(int, int) error {
		marked = true
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "bind socket to interface eth0") {
		t.Fatalf("error = %v, want bind context", err)
	}
	if marked {
		t.Fatal("socket was marked after bind failure")
	}
}

func TestConfigureLinuxSocket_ReportsMarkFailure(t *testing.T) {
	err := configureLinuxSocket(42, "eth0", func(int, string) error { return nil }, func(int, int) error {
		return errors.New("mark failed")
	})
	if err == nil || !strings.Contains(err.Error(), "mark socket for TUN bypass") {
		t.Fatalf("error = %v, want mark context", err)
	}
}
