package networkscan

import (
	"context"
	"testing"
	"time"
)

func TestScanRejectsHugeCIDR(t *testing.T) {
	s := New()
	if _, err := s.Scan(context.Background(), "10.0.0.0/8", nil, 100*time.Millisecond); err == nil {
		t.Fatal("CIDR /8 accettato")
	}
	if _, err := s.Scan(context.Background(), "0.0.0.0/0", nil, 100*time.Millisecond); err == nil {
		t.Fatal("CIDR /0 accettato")
	}
}

func TestScanRejectsPortAndTimeoutBounds(t *testing.T) {
	s := New()
	if _, err := s.Scan(context.Background(), "192.168.1.0/24", nil, 30*time.Second); err == nil {
		t.Fatal("timeout fuori bound accettato")
	}
	ports := make([]int, 21)
	for i := range ports {
		ports[i] = i + 1
	}
	if _, err := s.Scan(context.Background(), "192.168.1.0/24", ports, 100*time.Millisecond); err == nil {
		t.Fatal("troppe porte accettate")
	}
	if _, err := s.Scan(context.Background(), "192.168.1.0/24", []int{0}, 100*time.Millisecond); err == nil {
		t.Fatal("porta 0 accettata")
	}
	if _, err := s.Scan(context.Background(), "192.168.1.0/24", []int{}, 100*time.Millisecond); err == nil {
		t.Fatal("lista porte vuota accettata")
	}
}
