package service

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
	"github.com/ducnt114/gocloak/internal/store"
)

// RegistrationPolicyType is the component type of client registration policies.
const RegistrationPolicyType = "org.gocloak.services.clientregistration.policy.ClientRegistrationPolicy"

// registrationMapperTypes are the protocol mappers registered clients may use.
var registrationMapperTypes = []string{"oidc-usermodel-attribute-mapper", "oidc-usermodel-property-mapper", "oidc-full-name-mapper",
	"saml-user-property-mapper", "oidc-sha256-pairwise-sub-mapper", "saml-role-list-mapper", "oidc-address-mapper",
	"saml-user-attribute-mapper"}

// DefaultRegistrationPolicies are the client registration policies of new
// realms, for anonymous and authenticated registrations.
func DefaultRegistrationPolicies(realmID string) []*model.Component {
	mk := func(sub, name, provider string, cfg map[string][]string) *model.Component {
		if cfg == nil {
			cfg = map[string][]string{}
		}
		return &model.Component{ID: NewID(), RealmID: realmID, Name: name, ProviderID: provider, ProviderType: RegistrationPolicyType,
			ParentID: realmID, SubType: sub, Config: cfg}
	}
	return []*model.Component{
		mk("anonymous", "Trusted Hosts", "trusted-hosts", map[string][]string{
			"host-sending-registration-request-must-match": {"true"}, "client-uris-must-match": {"true"}}),
		mk("anonymous", "Consent Required", "consent-required", nil),
		mk("anonymous", "Full Scope Disabled", "scope", nil),
		mk("anonymous", "Max Clients Limit", "max-clients", map[string][]string{"max-clients": {"200"}}),
		mk("anonymous", "Allowed Protocol Mapper Types", "allowed-protocol-mappers", map[string][]string{
			"allowed-protocol-mapper-types": registrationMapperTypes}),
		mk("anonymous", "Allowed Client Scopes", "allowed-client-templates", map[string][]string{"allow-default-scopes": {"true"}}),
		mk("authenticated", "Allowed Protocol Mapper Types", "allowed-protocol-mappers", map[string][]string{
			"allowed-protocol-mapper-types": registrationMapperTypes}),
		mk("authenticated", "Allowed Client Scopes", "allowed-client-templates", map[string][]string{"allow-default-scopes": {"true"}}),
	}
}

func createRegistrationPolicies(ctx context.Context, st *store.Store, realmID string) error {
	for _, c := range DefaultRegistrationPolicies(realmID) {
		if err := st.CreateComponent(ctx, c); err != nil {
			return err
		}
	}
	return nil
}
