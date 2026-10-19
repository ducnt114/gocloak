package admin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/jwt"
)

// Client certificates (/clients/{id}/certificates/{attr}): the keys of
// private_key_jwt clients, stored in client attributes as Keycloak does
// (<attr>.certificate, <attr>.public.key, <attr>.private.key, <attr>.kid).

type certificateRep struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	Certificate string `json:"certificate,omitempty"`
	Kid         string `json:"kid,omitempty"`
}

func (h *Handler) getClientCertificate(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permViewClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	a := r.PathValue("attr")
	return ok(w, certificateRep{PrivateKey: c.Attributes[a+".private.key"], PublicKey: c.Attributes[a+".public.key"],
		Certificate: c.Attributes[a+".certificate"], Kid: c.Attributes[a+".kid"]})
}

// generateClientCertificate creates an RSA key pair with a self-signed
// certificate; the private key is returned once and kept, as in Keycloak.
func (h *Handler) generateClientCertificate(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixMilli()), Subject: pkix.Name{CommonName: c.ClientID},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().AddDate(10, 0, 0)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	a := r.PathValue("attr")
	rep := certificateRep{PrivateKey: base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(key)),
		Certificate: base64.StdEncoding.EncodeToString(der)}
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	c.Attributes[a+".private.key"], c.Attributes[a+".certificate"] = rep.PrivateKey, rep.Certificate
	delete(c.Attributes, a+".public.key")
	delete(c.Attributes, a+".kid")
	if err := h.Svc.Store.UpdateClient(r.Context(), c); err != nil {
		return err
	}
	return ok(w, rep)
}

// uploadClientCertificate stores a certificate, public key or JWKS sent as
// a multipart form (keystoreFormat, file), as the admin console does.
func (h *Handler) uploadClientCertificate(w http.ResponseWriter, r *http.Request, p *principal) error {
	realm, err := h.realmFor(r, p, permManageClients)
	if err != nil {
		return err
	}
	c, err := h.loadClient(r, realm)
	if err != nil {
		return err
	}
	if err := r.ParseMultipartForm(1 << 20); err != nil {
		return badRequest("expected a multipart form")
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		return badRequest("missing file")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return err
	}
	a := r.PathValue("attr")
	rep := certificateRep{}
	switch format := r.FormValue("keystoreFormat"); format {
	case "Certificate PEM":
		cert, err := jwt.ParseCertificate(string(data))
		if err != nil {
			return badRequest("invalid certificate")
		}
		rep.Certificate = base64.StdEncoding.EncodeToString(cert.Raw)
	case "Public Key PEM":
		blk, _ := pem.Decode(data)
		if blk == nil {
			return badRequest("invalid public key")
		}
		pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return badRequest("invalid public key")
		}
		rep.PublicKey = base64.StdEncoding.EncodeToString(blk.Bytes)
		rep.Kid = jwt.KeyID(pub)
	case "JSON Web Key Set":
		var set struct{ Keys []jwt.JWK }
		if err := json.Unmarshal(data, &set); err != nil || len(set.Keys) == 0 {
			return badRequest("invalid JWKS")
		}
		k, err := jwt.KeyFromJWK(set.Keys[0], "RS256")
		if err != nil {
			return badRequest(err.Error())
		}
		der, err := x509.MarshalPKIXPublicKey(k.Public)
		if err != nil {
			return badRequest(err.Error())
		}
		rep.PublicKey, rep.Kid = base64.StdEncoding.EncodeToString(der), set.Keys[0].Kid
		if k.Certificate != nil {
			rep.Certificate = base64.StdEncoding.EncodeToString(k.Certificate.Raw)
		}
	default:
		return badRequest("Unsupported keystore format: " + format)
	}
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	for suffix, v := range map[string]string{".certificate": rep.Certificate, ".public.key": rep.PublicKey, ".kid": rep.Kid} {
		if v == "" {
			delete(c.Attributes, a+suffix)
		} else {
			c.Attributes[a+suffix] = v
		}
	}
	if !strings.HasSuffix(r.URL.Path, "/upload-certificate") {
		delete(c.Attributes, a+".private.key")
	}
	if err := h.Svc.Store.UpdateClient(r.Context(), c); err != nil {
		return err
	}
	return ok(w, rep)
}

func (h *Handler) registerCertificateRoutes(R string, add func(string, handlerFunc)) {
	const C = "/clients/{id}/certificates/{attr}"
	add("GET "+R+C, h.getClientCertificate)
	add("POST "+R+C+"/generate", h.generateClientCertificate)
	add("POST "+R+C+"/upload", h.uploadClientCertificate)
	add("POST "+R+C+"/upload-certificate", h.uploadClientCertificate)
}
