package service

import (
	"context"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // artifact binding identifier
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"

	"github.com/ducnt114/gocloak/internal/jwt"
	"github.com/ducnt114/gocloak/internal/model"
)

// ProtocolSAML is the protocol of SAML clients, client scopes and mappers.
const ProtocolSAML = "saml"

// SAML client attributes.
const (
	SAMLServerSignature      = "saml.server.signature"
	SAMLAssertionSignature   = "saml.assertion.signature"
	SAMLClientSignature      = "saml.client.signature"
	SAMLForcePostBinding     = "saml.force.post.binding"
	SAMLSignatureAlgorithm   = "saml.signature.algorithm"
	SAMLCanonicalization     = "saml_signature_canonicalization_method"
	SAMLNameIDFormat         = "saml_name_id_format"
	SAMLForceNameIDFormat    = "saml_force_name_id_format"
	SAMLAuthnStatement       = "saml.authnstatement"
	SAMLEncrypt              = "saml.encrypt"
	SAMLEncryptionCert       = "saml.encryption.certificate"
	SAMLEncryptionAlgorithm  = "saml.encryption.algorithm"
	SAMLEncryptionKeyAlg     = "saml.encryption.keyAlgorithm"
	SAMLEncryptionDigest     = "saml.encryption.digestMethod"
	SAMLEncryptionMGF        = "saml.encryption.maskGenerationFunction"
	SAMLSigningCert          = "saml.signing.certificate"
	SAMLSigningKey           = "saml.signing.private.key"
	SAMLACSPost              = "saml_assertion_consumer_url_post"
	SAMLACSRedirect          = "saml_assertion_consumer_url_redirect"
	SAMLACSArtifact          = "saml_artifact_binding_url"
	SAMLSLOPost              = "saml_single_logout_service_url_post"
	SAMLSLORedirect          = "saml_single_logout_service_url_redirect"
	SAMLSLOSOAP              = "saml_single_logout_service_url_soap"
	SAMLSLOArtifact          = "saml_single_logout_service_url_artifact"
	SAMLIdPInitiatedName     = "saml_idp_initiated_sso_url_name"
	SAMLIdPInitiatedRelay    = "saml_idp_initiated_sso_relay_state"
	SAMLAssertionLifespan    = "saml.assertion.lifespan"
	SAMLArtifactBindingID    = "saml.artifact.binding.identifier"
	SAMLServerSigKeyInfoExt  = "saml.server.signature.keyinfo.ext"
	SAMLServerSigKeyInfoXfmr = "saml.server.signature.keyinfo.xmlSigKeyInfoKeyNameTransformer"
)

// SAML protocol mapper types.
const (
	SAMLMapperUserProperty   = "saml-user-property-mapper"
	SAMLMapperUserAttribute  = "saml-user-attribute-mapper"
	SAMLMapperRoleList       = "saml-role-list-mapper"
	SAMLMapperHardcodedAttr  = "saml-hardcode-attribute-mapper"
	SAMLMapperGroups         = "saml-group-membership-mapper"
	SAMLMapperHardcodedRole  = "saml-hardcode-role-mapper"
	SAMLMapperRoleName       = "saml-role-name-mapper"
	SAMLMapperSessionNote    = "saml-user-session-note-mapper"
	SAMLMapperAudience       = "saml-audience-mapper"
	SAMLMapperAudienceResolv = "saml-audience-resolve-mapper"
	SAMLMapperNameID         = "saml-user-attribute-nameid-mapper"
)

func init() {
	for _, t := range []string{SAMLMapperUserProperty, SAMLMapperUserAttribute, SAMLMapperRoleList, SAMLMapperHardcodedAttr,
		SAMLMapperGroups, SAMLMapperHardcodedRole, SAMLMapperRoleName, SAMLMapperSessionNote, SAMLMapperAudience,
		SAMLMapperAudienceResolv, SAMLMapperNameID,
		// organizations are not supported: their mappers (in the scopes of
		// upstream realm exports) are accepted and add nothing
		"saml-organization-membership-mapper", "oidc-organization-membership-mapper"} {
		MapperTypes[t] = true
	}
}

// samlDefaults are the attributes of a new SAML client.
var samlDefaults = map[string]string{
	"saml.allow.ecp.flow":  "false",
	SAMLAuthnStatement:     "true",
	SAMLClientSignature:    "true",
	SAMLForcePostBinding:   "true",
	SAMLServerSignature:    "true",
	SAMLSignatureAlgorithm: "RSA_SHA256",
	SAMLForceNameIDFormat:  "false",
	SAMLNameIDFormat:       "username",
	SAMLCanonicalization:   "http://www.w3.org/2001/10/xml-exc-c14n#",
}

// SetupSAMLClient applies the defaults to a SAML client being
// created: missing attributes, the artifact binding identifier and, when
// clients must sign their requests but no certificate was given, a
// generated key pair (so that the console can export it).
func SetupSAMLClient(c *model.Client) error {
	if c.Attributes == nil {
		c.Attributes = map[string]string{}
	}
	for k, v := range samlDefaults {
		if _, ok := c.Attributes[k]; !ok && v != "" {
			c.Attributes[k] = v
		}
	}
	if _, ok := c.Attributes[SAMLArtifactBindingID]; !ok {
		sum := sha1.Sum([]byte(c.ClientID)) //nolint:gosec
		c.Attributes[SAMLArtifactBindingID] = base64.StdEncoding.EncodeToString(sum[:])
	}
	if c.Attributes[SAMLClientSignature] == "true" && c.Attributes[SAMLSigningCert] == "" {
		key, err := jwt.GenerateRSA(2048, "RS256", c.ClientID)
		if err != nil {
			return err
		}
		priv := key.Private.(*rsa.PrivateKey)
		c.Attributes[SAMLSigningCert] = base64.StdEncoding.EncodeToString(key.Certificate.Raw)
		c.Attributes[SAMLSigningKey] = base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(priv))
	}
	return nil
}

// ParseCertificates parses a client certificate attribute: base64 DER (as
// the console stores it) or PEM, possibly several separated by commas.
func ParseCertificates(attr string) []*x509.Certificate {
	var out []*x509.Certificate
	rest := []byte(attr)
	if strings.Contains(attr, "-----BEGIN") {
		for {
			var b *pem.Block
			b, rest = pem.Decode(rest)
			if b == nil {
				break
			}
			if c, err := x509.ParseCertificate(b.Bytes); err == nil {
				out = append(out, c)
			}
		}
		return out
	}
	for _, part := range strings.Split(attr, ",") {
		part = strings.Join(strings.Fields(part), "")
		if part == "" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(part)
		if err != nil {
			continue
		}
		if c, err := x509.ParseCertificate(der); err == nil {
			out = append(out, c)
		}
	}
	return out
}

// BackchannelLogoutFunc notifies the clients of user sessions that are
// ended outside of a browser logout (by an administrator, the account
// console or a back-channel request). base is the server's public URL.
type BackchannelLogoutFunc func(ctx context.Context, base string, realm *model.Realm, sessions []*model.UserSession)

// BackchannelLogout runs the registered back-channel logout handlers.
func (s *Service) BackchannelLogout(ctx context.Context, base string, realm *model.Realm, sessions ...*model.UserSession) {
	if s.LogoutHandler != nil && len(sessions) > 0 {
		s.LogoutHandler(ctx, base, realm, sessions)
	}
}
