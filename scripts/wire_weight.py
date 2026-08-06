"""Wire ValidateAuthWeight into Manager.Register/Update on monitor-feature."""
p = 'sdk/cliproxy/auth/conductor.go'
with open(p, 'r', encoding='utf-8', newline='') as f:
    text = f.read()
crlf = '\r\n' in text
text = text.replace('\r\n', '\n')

old1 = """func (m *Manager) Register(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil {
		return nil, nil
	}
	if auth.ID == "" {
		auth.ID = uuid.NewString()
	}"""
new1 = """func (m *Manager) Register(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil {
		return nil, nil
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, fmt.Errorf("register auth: %w", errWeight)
	}
	if auth.ID == "" {
		auth.ID = uuid.NewString()
	}"""
assert old1 in text, 'register pattern not found'
text = text.replace(old1, new1)

old2 = """func (m *Manager) Update(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil || auth.ID == "" {
		return nil, nil
	}"""
new2 = """func (m *Manager) Update(ctx context.Context, auth *Auth) (*Auth, error) {
	if auth == nil || auth.ID == "" {
		return nil, nil
	}
	if errWeight := ValidateAuthWeight(auth); errWeight != nil {
		return nil, fmt.Errorf("update auth: %w", errWeight)
	}"""
assert old2 in text, 'update pattern not found'
text = text.replace(old2, new2)

out = text.replace('\n', '\r\n') if crlf else text
with open(p, 'w', encoding='utf-8', newline='') as f:
    f.write(out)
print('weight validation wired into Register/Update')
