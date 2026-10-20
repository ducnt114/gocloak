// Package authz evaluates authorization services policies: the
// permissions (resource and scope based) of a resource server, their
// policies (role, user, group, client, client scope, time, regex,
// aggregated and the default JavaScript policy), decision strategies,
// policy logic, enforcement modes, resource owners and UMA tickets.
package authz

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ducnt114/gocloak/internal/model"
)

// Policy and permission types, decision strategies and logic.
const (
	TypeResource = "resource"
	TypeScope    = "scope"

	Unanimous   = "UNANIMOUS"
	Affirmative = "AFFIRMATIVE"
	Consensus   = "CONSENSUS"

	Positive = "POSITIVE"
	Negative = "NEGATIVE"

	Enforcing  = "ENFORCING"
	Permissive = "PERMISSIVE"
	Disabled   = "DISABLED"
)

// DefaultPolicyCode is the code of the "Default Policy" created with a
// resource server: a JavaScript policy that grants. Other JavaScript
// policies are not supported and deny.
const DefaultPolicyCode = "// by default, grants any permission associated with this policy\n$evaluation.grant();\n"

// Data is a resource server with everything it holds.
type Data struct {
	Server    *model.ResourceServer
	Resources []*model.AuthzResource
	Scopes    []*model.AuthzScope
	Policies  []*model.AuthzPolicy
	Tickets   []*model.PermissionTicket

	scopeByID    map[string]*model.AuthzScope
	scopeByName  map[string]*model.AuthzScope
	policyByID   map[string]*model.AuthzPolicy
	resourceByID map[string]*model.AuthzResource
}

// Index builds the lookup tables; call it once the data is loaded.
func (d *Data) Index() {
	d.scopeByID, d.scopeByName = map[string]*model.AuthzScope{}, map[string]*model.AuthzScope{}
	for _, s := range d.Scopes {
		d.scopeByID[s.ID], d.scopeByName[s.Name] = s, s
	}
	d.policyByID = map[string]*model.AuthzPolicy{}
	for _, p := range d.Policies {
		d.policyByID[p.ID] = p
	}
	d.resourceByID = map[string]*model.AuthzResource{}
	for _, r := range d.Resources {
		d.resourceByID[r.ID] = r
	}
}

func (d *Data) Scope(id string) *model.AuthzScope         { return d.scopeByID[id] }
func (d *Data) ScopeByName(name string) *model.AuthzScope { return d.scopeByName[name] }
func (d *Data) Policy(id string) *model.AuthzPolicy       { return d.policyByID[id] }
func (d *Data) Resource(id string) *model.AuthzResource   { return d.resourceByID[id] }
func IsPermission(p *model.AuthzPolicy) bool              { return p.Type == TypeResource || p.Type == TypeScope }
func (d *Data) ResourceByName(name string) *model.AuthzResource {
	for _, r := range d.Resources {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// Group is a group of the identity.
type Group struct{ ID, Path string }

// Identity is who asks for access, and the context of the request.
type Identity struct {
	UserID       string
	Roles        map[string]bool // effective role ids
	Groups       []Group         // groups the user is a member of
	ClientID     string          // UUID of the client the token was issued to
	ClientScopes map[string]bool // ids of the client scopes of the token
	Claims       map[string]any  // claims of the token
	Attributes   map[string][]string
	Now          time.Time
}

// Requested is a resource (and scopes) to evaluate; an empty ResourceID
// with scopes asks for those scopes on any resource.
type Requested struct {
	ResourceID string
	Scopes     []string // scope ids; empty means all scopes of the resource
}

// PolicyDecision is the outcome of a policy, with the outcomes of the
// policies it is made of.
type PolicyDecision struct {
	Policy     *model.AuthzPolicy
	Granted    bool
	Scopes     []*model.AuthzScope // scopes a permission granted
	Associated []*PolicyDecision
}

// Result is the decision on one resource.
type Result struct {
	Resource  *model.AuthzResource
	Requested []*model.AuthzScope // the scopes evaluated
	Granted   []*model.AuthzScope // the scopes granted
	Allowed   bool                // the resource (or one of its scopes) is granted
	Decisions []*PolicyDecision   // the permissions that applied
}

// Evaluate decides on the requested resources; with no request, on all
// resources of the server (an entitlement).
func Evaluate(d *Data, id *Identity, requests []Requested) []*Result {
	if d.scopeByID == nil {
		d.Index()
	}
	if len(requests) == 0 {
		for _, r := range d.Resources {
			requests = append(requests, Requested{ResourceID: r.ID})
		}
	}
	var out []*Result
	for _, req := range requests {
		if req.ResourceID == "" {
			// scopes only: every resource holding one of them
			for _, r := range d.Resources {
				var common []string
				for _, s := range req.Scopes {
					if slices.Contains(r.ScopeIDs, s) {
						common = append(common, s)
					}
				}
				if len(common) > 0 {
					out = append(out, d.evaluateResource(id, r, common))
				}
			}
			continue
		}
		if r := d.Resource(req.ResourceID); r != nil {
			out = append(out, d.evaluateResource(id, r, req.Scopes))
		}
	}
	return out
}

func (d *Data) evaluateResource(id *Identity, r *model.AuthzResource, scopeIDs []string) *Result {
	res := &Result{Resource: r}
	if len(scopeIDs) == 0 {
		scopeIDs = r.ScopeIDs
	}
	for _, sid := range scopeIDs {
		if s := d.Scope(sid); s != nil {
			res.Requested = append(res.Requested, s)
		}
	}
	grantAll := func() *Result {
		res.Granted, res.Allowed = res.Requested, true
		return res
	}
	if d.Server.PolicyEnforcementMode == Disabled {
		return grantAll()
	}
	if id.UserID != "" && r.Owner == id.UserID {
		return grantAll() // owners have access to their resources
	}

	// the permissions that apply, each with the requested scopes it covers
	type applied struct {
		decision *PolicyDecision
		scopes   map[string]bool // nil: the whole resource
	}
	var perms []applied
	for _, p := range d.Policies {
		if !IsPermission(p) {
			continue
		}
		resourceType := p.Config["defaultResourceType"]
		matchesResource := slices.Contains(p.ResourceIDs, r.ID) || (resourceType != "" && resourceType == r.Type)
		switch p.Type {
		case TypeResource:
			if !matchesResource {
				continue
			}
			dec := d.evaluatePolicy(id, p, map[string]bool{})
			perms = append(perms, applied{dec, nil})
		case TypeScope:
			if len(p.ResourceIDs) > 0 && !slices.Contains(p.ResourceIDs, r.ID) {
				continue
			}
			if resourceType != "" && resourceType != r.Type {
				continue
			}
			covered := map[string]bool{}
			for _, s := range res.Requested {
				if slices.Contains(p.ScopeIDs, s.ID) {
					covered[s.ID] = true
				}
			}
			if len(covered) == 0 {
				continue
			}
			dec := d.evaluatePolicy(id, p, map[string]bool{})
			perms = append(perms, applied{dec, covered})
		}
	}
	for _, a := range perms {
		if a.decision.Granted {
			for _, s := range res.Requested {
				if a.scopes == nil || a.scopes[s.ID] {
					a.decision.Scopes = append(a.decision.Scopes, s)
				}
			}
		}
		res.Decisions = append(res.Decisions, a.decision)
	}

	// granted UMA tickets
	ticketScopes := map[string]bool{}
	ticketResource := false
	for _, t := range d.Tickets {
		if t.ResourceID == r.ID && t.Requester == id.UserID && t.GrantedTimestamp > 0 {
			if t.ScopeID == "" {
				ticketResource = true
			} else {
				ticketScopes[t.ScopeID] = true
			}
		}
	}

	decide := func(scopeID string) bool {
		if ticketResource || (scopeID != "" && ticketScopes[scopeID]) {
			return true
		}
		granted, denied := 0, 0
		for _, a := range perms {
			if scopeID != "" && a.scopes != nil && !a.scopes[scopeID] {
				continue
			}
			if scopeID == "" && a.scopes != nil {
				continue
			}
			if a.decision.Granted {
				granted++
			} else {
				denied++
			}
		}
		if granted+denied == 0 {
			return d.Server.PolicyEnforcementMode == Permissive
		}
		switch d.Server.DecisionStrategy {
		case Affirmative:
			return granted > 0
		case Consensus:
			return granted > denied
		}
		return denied == 0
	}
	for _, s := range res.Requested {
		if decide(s.ID) {
			res.Granted = append(res.Granted, s)
		}
	}
	if len(res.Requested) == 0 {
		res.Allowed = decide("")
	} else {
		res.Allowed = len(res.Granted) > 0
	}
	return res
}

// evaluatePolicy evaluates a policy or a permission (its policies).
func (d *Data) evaluatePolicy(id *Identity, p *model.AuthzPolicy, seen map[string]bool) *PolicyDecision {
	dec := &PolicyDecision{Policy: p}
	if seen[p.ID] {
		return dec // a cycle denies
	}
	seen[p.ID] = true
	defer delete(seen, p.ID)
	var granted bool
	switch p.Type {
	case TypeResource, TypeScope, "aggregate":
		permit, deny := 0, 0
		for _, aid := range p.AssociatedIDs {
			ap := d.Policy(aid)
			if ap == nil {
				continue
			}
			sub := d.evaluatePolicy(id, ap, seen)
			dec.Associated = append(dec.Associated, sub)
			if sub.Granted {
				permit++
			} else {
				deny++
			}
		}
		switch p.DecisionStrategy {
		case Affirmative:
			granted = permit > 0
		case Consensus:
			granted = permit > deny
		default:
			granted = permit > 0 && deny == 0
		}
	default:
		granted = evaluateRule(id, p)
	}
	if p.Logic == Negative {
		granted = !granted
	}
	dec.Granted = granted
	return dec
}

type ref struct {
	ID             string `json:"id"`
	Required       bool   `json:"required"`
	Path           string `json:"path,omitempty"`
	ExtendChildren bool   `json:"extendChildren,omitempty"`
}

func refs(raw string) []ref {
	var out []ref
	if json.Unmarshal([]byte(raw), &out) == nil {
		return out
	}
	var ids []string
	if json.Unmarshal([]byte(raw), &ids) == nil {
		for _, id := range ids {
			out = append(out, ref{ID: id})
		}
	}
	return out
}

// ids reads a JSON list of ids.
func ids(raw string) []string {
	var out []string
	for _, r := range refs(raw) {
		out = append(out, r.ID)
	}
	return out
}

// requiredMatch implements role and client scope policies: every required
// entry must match, and at least one entry must match.
func requiredMatch(entries []ref, has func(string) bool) bool {
	any := false
	for _, e := range entries {
		ok := has(e.ID)
		if e.Required && !ok {
			return false
		}
		any = any || ok
	}
	return any
}

// evaluateRule evaluates an identity, time or regex policy.
func evaluateRule(id *Identity, p *model.AuthzPolicy) bool {
	c := p.Config
	switch p.Type {
	case "role":
		return requiredMatch(refs(c["roles"]), func(rid string) bool { return id.Roles[rid] })
	case "user":
		return id.UserID != "" && slices.Contains(ids(c["users"]), id.UserID)
	case "client":
		return slices.Contains(ids(c["clients"]), id.ClientID)
	case "client-scope":
		return requiredMatch(refs(c["clientScopes"]), func(sid string) bool { return id.ClientScopes[sid] })
	case "group":
		return groupMatch(id, refs(c["groups"]), c["groupsClaim"])
	case "time":
		return timeMatch(id.Now, c)
	case "regex":
		return regexMatch(id, c)
	case "js":
		return strings.TrimSpace(c["code"]) == strings.TrimSpace(DefaultPolicyCode)
	}
	return false
}

func groupMatch(id *Identity, groups []ref, claim string) bool {
	var paths []string
	if claim != "" {
		for _, v := range claimStrings(lookup(id.Claims, claim)) {
			if !strings.HasPrefix(v, "/") {
				v = "/" + v
			}
			paths = append(paths, v)
		}
	} else {
		for _, g := range id.Groups {
			paths = append(paths, g.Path)
		}
	}
	for _, g := range groups {
		for i, path := range paths {
			if (claim == "" && id.Groups[i].ID == g.ID) || (g.Path != "" && path == g.Path) {
				return true
			}
			if g.ExtendChildren && g.Path != "" && strings.HasPrefix(path, g.Path+"/") {
				return true
			}
		}
	}
	return false
}

const timeLayout = "2006-01-02 15:04:05"

// timeMatch checks the time policy bounds: nbf / noa dates and ranges of
// day of month, month, year, hour and minute.
func timeMatch(now time.Time, c map[string]string) bool {
	if v := c["nbf"]; v != "" {
		if t, err := time.ParseInLocation(timeLayout, v, time.Local); err == nil && now.Before(t) {
			return false
		}
	}
	if v := c["noa"]; v != "" {
		if t, err := time.ParseInLocation(timeLayout, v, time.Local); err == nil && !now.Before(t) {
			return false
		}
	}
	for _, f := range []struct {
		key   string
		value int
	}{{"dayMonth", now.Day()}, {"month", int(now.Month())}, {"year", now.Year()}, {"hour", now.Hour()}, {"minute", now.Minute()}} {
		from, err := strconv.Atoi(c[f.key])
		if err != nil {
			continue
		}
		to := from
		if e, err := strconv.Atoi(c[f.key+"End"]); err == nil {
			to = e
		}
		if f.value < from || f.value > to {
			return false
		}
	}
	return true
}

func regexMatch(id *Identity, c map[string]string) bool {
	re, err := regexp.Compile("^(?:" + c["pattern"] + ")$")
	if err != nil || c["targetClaim"] == "" {
		return false
	}
	var values []string
	if c["targetContextAttributes"] == "true" {
		values = id.Attributes[c["targetClaim"]]
	} else {
		values = claimStrings(lookup(id.Claims, c["targetClaim"]))
	}
	for _, v := range values {
		if re.MatchString(v) {
			return true
		}
	}
	return false
}

// lookup reads a claim by dotted path.
func lookup(claims map[string]any, path string) any {
	var v any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[part]
	}
	return v
}

func claimStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			out = append(out, claimStrings(x)...)
		}
		return out
	case []string:
		return t
	}
	return []string{fmt.Sprint(v)}
}

// Permission is an entry of an RPT's authorization claim.
type Permission struct {
	ResourceID   string   `json:"rsid,omitempty"`
	ResourceName string   `json:"rsname,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`
}

// Permissions lists what the results grant, as RPT permissions.
func Permissions(results []*Result, includeNames bool) []Permission {
	var out []Permission
	for _, r := range results {
		if !r.Allowed {
			continue
		}
		p := Permission{ResourceID: r.Resource.ID}
		if includeNames {
			p.ResourceName = r.Resource.Name
		}
		for _, s := range r.Granted {
			p.Scopes = append(p.Scopes, s.Name)
		}
		out = append(out, p)
	}
	return out
}

// Merge adds the permissions of a previous RPT (upgrade).
func Merge(old, add []Permission) []Permission {
	byID := map[string]*Permission{}
	var order []string
	for _, list := range [][]Permission{old, add} {
		for _, p := range list {
			e := byID[p.ResourceID]
			if e == nil {
				cp := p
				cp.Scopes = append([]string(nil), p.Scopes...)
				byID[p.ResourceID] = &cp
				order = append(order, p.ResourceID)
				continue
			}
			for _, s := range p.Scopes {
				if !slices.Contains(e.Scopes, s) {
					e.Scopes = append(e.Scopes, s)
				}
			}
		}
	}
	out := make([]Permission, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}

// SortScopes orders scopes by name.
func SortScopes(list []*model.AuthzScope) {
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
}
