// tlsproxy terminates TLS (self-signed) in front of an HTTP server, setting
// X-Forwarded-* headers. usage: tlsproxy LISTEN BACKEND
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"
)

func main() {
	backend, _ := url.Parse(os.Args[2])
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	rp := httputil.NewSingleHostReverseProxy(backend)
	orig := rp.Director
	rp.Director = func(r *http.Request) {
		host := r.Host
		orig(r)
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Forwarded-Host", host)
		_, port, _ := net.SplitHostPort(host)
		r.Header.Set("X-Forwarded-Port", port)
		r.Host = host
	}
	srv := &http.Server{Addr: os.Args[1], Handler: rp, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
