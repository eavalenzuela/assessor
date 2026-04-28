package network

import (
	"net"
	"testing"
)

func TestParseHexAddr(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantIP   string
		wantPort int
		wantErr  bool
	}{
		{name: "ipv4 loopback:22", in: "0100007F:0016", wantIP: "127.0.0.1", wantPort: 22},
		{name: "ipv4 wildcard:80", in: "00000000:0050", wantIP: "0.0.0.0", wantPort: 80},
		{name: "ipv4 high port", in: "0100007F:1F90", wantIP: "127.0.0.1", wantPort: 8080},
		{
			name: "ipv6 loopback:443",
			in:   "00000000000000000000000001000000:01BB",
			// Per kernel proc encoding, each 32-bit word is little-endian.
			wantIP:   "::1",
			wantPort: 443,
		},
		{name: "missing colon", in: "01000000", wantErr: true},
		{name: "bad hex", in: "ZZZZ:0016", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ip, port, err := parseHexAddr(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v:%d", ip, port)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !ip.Equal(net.ParseIP(tc.wantIP)) {
				t.Errorf("ip = %v, want %v", ip, tc.wantIP)
			}
			if port != tc.wantPort {
				t.Errorf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}
