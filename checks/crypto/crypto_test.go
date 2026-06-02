package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/t3rmit3/assessor/internal/finding"
)

func makeCertPEM(t *testing.T, cn string, notAfter time.Time, bits int, sigAlg x509.SignatureAlgorithm) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: cn},
		NotBefore:          notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:           notAfter,
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func makeRSAKeyPEM(t *testing.T, bits int) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func TestScanCertExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	expired := makeCertPEM(t, "old.example", now.Add(-24*time.Hour), 2048, x509.SHA256WithRSA)
	soon := makeCertPEM(t, "soon.example", now.Add(10*24*time.Hour), 2048, x509.SHA256WithRSA)
	good := makeCertPEM(t, "good.example", now.Add(400*24*time.Hour), 2048, x509.SHA256WithRSA)

	t.Run("expired", func(t *testing.T) {
		bad, evs := scanCertExpiry(expired, "/etc/ssl/old.pem", now)
		if len(bad) != 1 || !strings.HasPrefix(bad[0], "EXPIRED") {
			t.Fatalf("got %v, want one EXPIRED entry", bad)
		}
		if len(evs) != 1 {
			t.Errorf("evidence = %d, want 1", len(evs))
		}
	})
	t.Run("near expiry", func(t *testing.T) {
		bad, _ := scanCertExpiry(soon, "/etc/ssl/soon.pem", now)
		if len(bad) != 1 || !strings.HasPrefix(bad[0], "expiring") {
			t.Fatalf("got %v, want one expiring entry", bad)
		}
	})
	t.Run("healthy", func(t *testing.T) {
		if bad, _ := scanCertExpiry(good, "/etc/ssl/good.pem", now); len(bad) != 0 {
			t.Errorf("healthy cert flagged: %v", bad)
		}
	})
	t.Run("concatenated PEM", func(t *testing.T) {
		combined := append(append([]byte{}, good...), expired...)
		bad, _ := scanCertExpiry(combined, "/etc/ssl/bundle.pem", now)
		if len(bad) != 1 {
			t.Errorf("got %d, want 1 (only the expired one)", len(bad))
		}
	})
	t.Run("non-cert blocks ignored", func(t *testing.T) {
		key := makeRSAKeyPEM(t, 2048)
		if bad, _ := scanCertExpiry(key, "/etc/ssl/key.pem", now); len(bad) != 0 {
			t.Errorf("key block should be ignored, got %v", bad)
		}
	})
}

func TestScanWeakKeys(t *testing.T) {
	t.Run("weak cert key", func(t *testing.T) {
		weak := makeCertPEM(t, "weak.example", time.Now().Add(time.Hour), 1024, x509.SHA256WithRSA)
		bad, evs := scanWeakKeys(weak, "/etc/ssl/weak.crt")
		if len(bad) != 1 || !strings.Contains(bad[0], "RSA 1024") {
			t.Fatalf("got %v, want RSA 1024 flag", bad)
		}
		if len(evs) != 1 {
			t.Errorf("evidence = %d, want 1", len(evs))
		}
	})
	t.Run("strong cert key", func(t *testing.T) {
		strong := makeCertPEM(t, "strong.example", time.Now().Add(time.Hour), 2048, x509.SHA256WithRSA)
		if bad, _ := scanWeakKeys(strong, "/etc/ssl/strong.crt"); len(bad) != 0 {
			t.Errorf("strong cert flagged: %v", bad)
		}
	})
	t.Run("weak private key", func(t *testing.T) {
		key := makeRSAKeyPEM(t, 1024)
		bad, _ := scanWeakKeys(key, "/etc/ssl/weak.key")
		if len(bad) != 1 || !strings.Contains(bad[0], "RSA private 1024") {
			t.Fatalf("got %v, want RSA private 1024 flag", bad)
		}
	})
	t.Run("weak signature algorithm", func(t *testing.T) {
		sha1cert := makeCertPEM(t, "sha1.example", time.Now().Add(time.Hour), 2048, x509.SHA1WithRSA)
		bad, _ := scanWeakKeys(sha1cert, "/etc/ssl/sha1.crt")
		if len(bad) != 1 || !strings.Contains(bad[0], "weak sig") {
			t.Fatalf("got %v, want weak-sig flag", bad)
		}
	})
}

func TestClassifyCryptoPolicy(t *testing.T) {
	cases := []struct {
		in   string
		want finding.Status
	}{
		{"LEGACY", finding.StatusFail},
		{"DEFAULT", finding.StatusPass},
		{"FUTURE", finding.StatusPass},
		{"FIPS", finding.StatusPass},
		{"DEFAULT:SHA1", finding.StatusWarn},
		{"CUSTOM", finding.StatusWarn},
	}
	for _, tc := range cases {
		if got, _ := classifyCryptoPolicy(tc.in); got != tc.want {
			t.Errorf("classifyCryptoPolicy(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
