package adminconsole

import "testing"

func TestRebrand(t *testing.T) {
	for in, want := range map[string]string{
		"Keycloak":                                 "gocloak",
		"Sign in to Keycloak's console":            "Sign in to gocloak's console",
		"KEYCLOAK_SESSION":                         "GOCLOAK_SESSION",
		"keycloak__form keycloak.v2":               "gocloak__form gocloak.v2",
		"org.keycloak.storage.UserStorageProvider": "org.gocloak.storage.UserStorageProvider",
		"fedToKeycloak keycloakToFed":              "fedToGocloak gocloakToFed",
		"addKeycloakOpenIdProvider":                "addGocloakOpenIdProvider",
		"see https://www.keycloak.org/docs/latest": "see https://www.keycloak.org/docs/latest",
		"https://github.com/keycloak/keycloak":     "https://github.com/keycloak/keycloak",
		"nothing to change":                        "nothing to change",
	} {
		if got := Rebrand(in); got != want {
			t.Errorf("Rebrand(%q) = %q, want %q", in, got, want)
		}
	}
}
