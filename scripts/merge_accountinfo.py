"""Merge AccountInfo: upstream AuthKind logic + keep local gemini-cli project_id enhancement."""
p = 'sdk/cliproxy/auth/types.go'
with open(p, 'r', encoding='utf-8', newline='') as f:
    text = f.read()
crlf = '\r\n' in text
text = text.replace('\r\n', '\n')

start = text.index('func (a *Auth) AccountInfo() (string, string) {')
end = text.index('// ExpirationTime attempts to extract', start)
old = text[start:end]

new = '''func (a *Auth) AccountInfo() (string, string) {
	if a == nil {
		return "", ""
	}
	// For Gemini CLI, include project ID in the OAuth account info if present.
	if strings.ToLower(a.Provider) == "gemini-cli" {
		if a.Metadata != nil {
			email, _ := a.Metadata["email"].(string)
			email = strings.TrimSpace(email)
			if email != "" {
				if p, ok := a.Metadata["project_id"].(string); ok {
					p = strings.TrimSpace(p)
					if p != "" {
						return "oauth", email + " (" + p + ")"
					}
				}
				return "oauth", email
			}
		}
	}
	switch a.AuthKind() {
	case AuthKindOAuth:
		if a.Metadata != nil {
			if v, ok := a.Metadata["email"].(string); ok {
				email := strings.TrimSpace(v)
				if email != "" {
					return "oauth", email
				}
			}
		}
		return "oauth", ""
	case AuthKindAPIKey:
		if apiKey := authAttribute(a, AttributeAPIKey); apiKey != "" {
			return "api_key", apiKey
		}
		return "api_key", ""
	default:
		return "", ""
	}
}

'''
text = text[:start] + new + text[end:]
out = text.replace('\n', '\r\n') if crlf else text
with open(p, 'w', encoding='utf-8', newline='') as f:
    f.write(out)
print('AccountInfo merged')
