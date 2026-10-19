package userprofile

import (
	"encoding/json"
	"testing"
)

func TestDefaultProfile(t *testing.T) {
	c := Default(false)
	check := func(values map[string][]string, context, want string) {
		t.Helper()
		errs := c.Validate(values, context, nil)
		got := ""
		if len(errs) > 0 {
			got = errs[0].Field + ":" + errs[0].ErrorMessage
		}
		if got != want {
			t.Errorf("%v (%s): got %q want %q", values, context, got, want)
		}
	}
	check(map[string][]string{"username": {"bob"}}, ContextAdmin, "")
	check(map[string][]string{"username": {"bob"}}, ContextUser, "email:error-user-attribute-required")
	check(map[string][]string{"username": {"ab"}}, ContextAdmin, "username:error-invalid-length")
	check(map[string][]string{"username": {"bob"}, "email": {"not-an-email"}}, ContextAdmin, "email:error-invalid-email")
	check(map[string][]string{"username": {"bob"}, "firstName": {"<script>"}}, ContextAdmin, "firstName:error-person-name-invalid-character")
	check(map[string][]string{"username": {"bob smith"}}, ContextAdmin, "username:error-username-invalid-character")
	check(map[string][]string{"username": {"bob@example.com"}, "email": {"bob@example.com"}, "firstName": {"Bob"}, "lastName": {"B"}}, ContextUser, "")
	if errs := Default(true).Validate(map[string][]string{"username": {"admin"}}, ContextUser, nil); len(errs) != 0 {
		t.Fatalf("master profile requires nothing: %v", errs)
	}
	errs := c.Validate(map[string][]string{"username": {"ab"}}, ContextAdmin, nil)
	b, _ := json.Marshal(errs[0])
	if string(b) != `{"field":"username","errorMessage":"error-invalid-length","params":["username",3,255]}` {
		t.Fatalf("error JSON = %s", b)
	}
}

func TestCustomAttributes(t *testing.T) {
	c, err := Parse([]byte(`{"attributes":[{"name":"username"},{"name":"email"},
		{"name":"phone","validations":{"pattern":{"pattern":"^\\+[0-9]+$","error-message":"bad phone"}},"required":{"roles":["admin"]}},
		{"name":"age","validations":{"integer":{"min":18,"max":120}}},
		{"name":"color","validations":{"options":{"options":["red","blue"]}}}],
		"unmanagedAttributePolicy":"ADMIN_VIEW"}`))
	if err != nil {
		t.Fatal(err)
	}
	if errs := c.Validate(map[string][]string{"username": {"bob"}}, ContextAdmin, nil); len(errs) != 1 || errs[0].ErrorMessage != "error-user-attribute-required" {
		t.Fatalf("required phone: %v", errs)
	}
	errs := c.Validate(map[string][]string{"username": {"bob"}, "phone": {"123"}, "age": {"7"}, "color": {"green"}}, ContextAdmin, nil)
	if len(errs) != 3 || errs[0].ErrorMessage != "bad phone" || errs[1].ErrorMessage != "error-number-out-of-range" || errs[2].ErrorMessage != "error-invalid-value" {
		t.Fatalf("errors = %v", errs)
	}
	if !c.CanView("dept", ContextAdmin) || c.CanEdit("dept", ContextAdmin) || c.CanView("dept", ContextUser) {
		t.Fatal("ADMIN_VIEW permissions")
	}
	if _, err := Parse([]byte(`{"attributes":[{"name":"username"},{"name":"email","validations":{"nope":{}}}]}`)); err == nil {
		t.Fatal("unknown validator accepted")
	}
}
