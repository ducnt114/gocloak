package store

import (
	"context"

	"github.com/ducnt114/gocloak/internal/model"
)

// ---- flows ----

const flowCols = `id, realm_id, alias, description, provider_id, top_level, built_in`

func scanFlow(sc scanner) (*model.AuthFlow, error) {
	f := &model.AuthFlow{}
	if err := sc.Scan(&f.ID, &f.RealmID, &f.Alias, &f.Description, &f.ProviderID, &f.TopLevel, &f.BuiltIn); err != nil {
		return nil, mapErr(err)
	}
	return f, nil
}

func (s *Store) CreateFlow(ctx context.Context, f *model.AuthFlow) error {
	return s.exec(ctx, `INSERT INTO auth_flows (`+flowCols+`) VALUES (?,?,?,?,?,?,?)`,
		f.ID, f.RealmID, f.Alias, f.Description, f.ProviderID, f.TopLevel, f.BuiltIn)
}

func (s *Store) UpdateFlow(ctx context.Context, f *model.AuthFlow) error {
	return s.execOne(ctx, `UPDATE auth_flows SET alias=?, description=?, provider_id=?, top_level=?, built_in=? WHERE id=?`,
		f.Alias, f.Description, f.ProviderID, f.TopLevel, f.BuiltIn, f.ID)
}

// DeleteFlow deletes a flow, its executions and, recursively, its sub flows.
func (s *Store) DeleteFlow(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		subs, err := queryStrings(ctx, tx, `SELECT sub_flow_id FROM auth_executions WHERE flow_id=? AND sub_flow_id<>''`, id)
		if err != nil {
			return err
		}
		for _, sub := range subs {
			if err := tx.DeleteFlow(ctx, sub); err != nil {
				return err
			}
		}
		return tx.execOne(ctx, `DELETE FROM auth_flows WHERE id=?`, id)
	})
}

func (s *Store) GetFlow(ctx context.Context, realmID, id string) (*model.AuthFlow, error) {
	return scanFlow(s.q.QueryRowContext(ctx, `SELECT `+flowCols+` FROM auth_flows WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) GetFlowByAlias(ctx context.Context, realmID, alias string) (*model.AuthFlow, error) {
	return scanFlow(s.q.QueryRowContext(ctx, `SELECT `+flowCols+` FROM auth_flows WHERE realm_id=? AND alias=?`, realmID, alias))
}

func (s *Store) ListFlows(ctx context.Context, realmID string) ([]*model.AuthFlow, error) {
	return queryList(ctx, s, scanFlow, `SELECT `+flowCols+` FROM auth_flows WHERE realm_id=? ORDER BY alias`, realmID)
}

func (s *Store) CountFlows(ctx context.Context, realmID string) (int, error) {
	var n int
	err := s.q.QueryRowContext(ctx, `SELECT count(*) FROM auth_flows WHERE realm_id=?`, realmID).Scan(&n)
	return n, err
}

// ---- executions ----

const executionCols = `id, realm_id, flow_id, authenticator, sub_flow_id, requirement, priority, config_id`

func scanExecution(sc scanner) (*model.AuthExecution, error) {
	e := &model.AuthExecution{}
	if err := sc.Scan(&e.ID, &e.RealmID, &e.FlowID, &e.Authenticator, &e.SubFlowID, &e.Requirement, &e.Priority, &e.ConfigID); err != nil {
		return nil, mapErr(err)
	}
	return e, nil
}

func (s *Store) CreateExecution(ctx context.Context, e *model.AuthExecution) error {
	return s.exec(ctx, `INSERT INTO auth_executions (`+executionCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		e.ID, e.RealmID, e.FlowID, e.Authenticator, e.SubFlowID, e.Requirement, e.Priority, e.ConfigID)
}

func (s *Store) UpdateExecution(ctx context.Context, e *model.AuthExecution) error {
	return s.execOne(ctx, `UPDATE auth_executions SET requirement=?, priority=?, config_id=? WHERE id=?`,
		e.Requirement, e.Priority, e.ConfigID, e.ID)
}

func (s *Store) DeleteExecution(ctx context.Context, id string) error {
	return s.execOne(ctx, `DELETE FROM auth_executions WHERE id=?`, id)
}

func (s *Store) GetExecution(ctx context.Context, realmID, id string) (*model.AuthExecution, error) {
	return scanExecution(s.q.QueryRowContext(ctx, `SELECT `+executionCols+` FROM auth_executions WHERE realm_id=? AND id=?`, realmID, id))
}

// ListExecutions returns a flow's executions by priority.
func (s *Store) ListExecutions(ctx context.Context, flowID string) ([]*model.AuthExecution, error) {
	return queryList(ctx, s, scanExecution, `SELECT `+executionCols+` FROM auth_executions WHERE flow_id=? ORDER BY priority, id`, flowID)
}

// ---- authenticator configs ----

func scanAuthConfig(sc scanner) (*model.AuthenticatorConfig, error) {
	c := &model.AuthenticatorConfig{Config: map[string]string{}}
	if err := sc.Scan(&c.ID, &c.RealmID, &c.Alias, jsonCol{&c.Config}); err != nil {
		return nil, mapErr(err)
	}
	return c, nil
}

func (s *Store) CreateAuthConfig(ctx context.Context, c *model.AuthenticatorConfig) error {
	if c.Config == nil {
		c.Config = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO authenticator_configs (id, realm_id, alias, config) VALUES (?,?,?,?)`, c.ID, c.RealmID, c.Alias, toJSON(c.Config))
}

func (s *Store) UpdateAuthConfig(ctx context.Context, c *model.AuthenticatorConfig) error {
	return s.execOne(ctx, `UPDATE authenticator_configs SET alias=?, config=? WHERE id=?`, c.Alias, toJSON(c.Config), c.ID)
}

func (s *Store) DeleteAuthConfig(ctx context.Context, id string) error {
	return s.WithTx(ctx, func(tx *Store) error {
		if err := tx.exec(ctx, `UPDATE auth_executions SET config_id='' WHERE config_id=?`, id); err != nil {
			return err
		}
		return tx.execOne(ctx, `DELETE FROM authenticator_configs WHERE id=?`, id)
	})
}

func (s *Store) GetAuthConfig(ctx context.Context, realmID, id string) (*model.AuthenticatorConfig, error) {
	return scanAuthConfig(s.q.QueryRowContext(ctx, `SELECT id, realm_id, alias, config FROM authenticator_configs WHERE realm_id=? AND id=?`, realmID, id))
}

func (s *Store) ListAuthConfigs(ctx context.Context, realmID string) ([]*model.AuthenticatorConfig, error) {
	return queryList(ctx, s, scanAuthConfig, `SELECT id, realm_id, alias, config FROM authenticator_configs WHERE realm_id=? ORDER BY alias`, realmID)
}

// ---- required actions ----

const requiredActionCols = `realm_id, alias, name, provider_id, enabled, default_action, priority, config`

func scanRequiredAction(sc scanner) (*model.RequiredActionProvider, error) {
	a := &model.RequiredActionProvider{Config: map[string]string{}}
	if err := sc.Scan(&a.RealmID, &a.Alias, &a.Name, &a.ProviderID, &a.Enabled, &a.DefaultAction, &a.Priority, jsonCol{&a.Config}); err != nil {
		return nil, mapErr(err)
	}
	return a, nil
}

func (s *Store) CreateRequiredAction(ctx context.Context, a *model.RequiredActionProvider) error {
	if a.Config == nil {
		a.Config = map[string]string{}
	}
	return s.exec(ctx, `INSERT INTO required_actions (`+requiredActionCols+`) VALUES (?,?,?,?,?,?,?,?)`,
		a.RealmID, a.Alias, a.Name, a.ProviderID, a.Enabled, a.DefaultAction, a.Priority, toJSON(a.Config))
}

func (s *Store) UpdateRequiredAction(ctx context.Context, a *model.RequiredActionProvider) error {
	if a.Config == nil {
		a.Config = map[string]string{}
	}
	return s.execOne(ctx, `UPDATE required_actions SET name=?, enabled=?, default_action=?, priority=?, config=? WHERE realm_id=? AND alias=?`,
		a.Name, a.Enabled, a.DefaultAction, a.Priority, toJSON(a.Config), a.RealmID, a.Alias)
}

func (s *Store) DeleteRequiredAction(ctx context.Context, realmID, alias string) error {
	return s.execOne(ctx, `DELETE FROM required_actions WHERE realm_id=? AND alias=?`, realmID, alias)
}

func (s *Store) GetRequiredAction(ctx context.Context, realmID, alias string) (*model.RequiredActionProvider, error) {
	return scanRequiredAction(s.q.QueryRowContext(ctx, `SELECT `+requiredActionCols+` FROM required_actions WHERE realm_id=? AND alias=?`, realmID, alias))
}

func (s *Store) ListRequiredActions(ctx context.Context, realmID string) ([]*model.RequiredActionProvider, error) {
	return queryList(ctx, s, scanRequiredAction, `SELECT `+requiredActionCols+` FROM required_actions WHERE realm_id=? ORDER BY priority, alias`, realmID)
}
