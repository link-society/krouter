package auth

import (
	"html/template"

	"net/http"
)

// loginPage is the gateway-served login page: minimal, self-contained,
// no external assets; branding is deferred work
// (docs/spec/authentication.md Login page).
var loginPage = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex">
  <title>Sign in</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #f5f5f5;
           display: flex; justify-content: center; padding-top: 10vh; }
    main { background: #fff; border: 1px solid #ddd; border-radius: 4px;
           padding: 2rem; width: 20rem; }
    h1 { font-size: 1.1rem; margin: 0 0 1.5rem; }
    a.provider { display: block; text-align: center; margin: .5rem 0;
                 padding: .6rem; border: 1px solid #3273dc; border-radius: 4px;
                 color: #3273dc; text-decoration: none; }
    a.provider:hover { background: #3273dc; color: #fff; }
    hr { border: 0; border-top: 1px solid #ddd; margin: 1.2rem 0; }
    label { display: block; font-size: .85rem; margin: .6rem 0 .2rem; }
    input { width: 100%; box-sizing: border-box; padding: .45rem;
            border: 1px solid #ccc; border-radius: 4px; }
    button { width: 100%; margin-top: 1rem; padding: .6rem;
             background: #3273dc; color: #fff; border: 0; border-radius: 4px;
             cursor: pointer; }
    p.failure { color: #cc0f35; font-size: .85rem; }
  </style>
</head>
<body>
<main>
  <h1>Sign in</h1>
  {{- if .Failure}}
  <p class="failure">Sign-in failed. Check your credentials and try again.</p>
  {{- end}}
  {{- range .Providers}}
  <a class="provider" href="{{.URL}}">Continue with {{.Name}}</a>
  {{- end}}
  {{- if and .Providers .Form}}
  <hr>
  {{- end}}
  {{- if .Form}}
  <form method="post" action="{{.Form.Action}}">
    <input type="hidden" name="token" value="{{.Form.Token}}">
    <label for="username">Username</label>
    <input type="text" id="username" name="username" autocomplete="username" required>
    <label for="password">Password</label>
    <input type="password" id="password" name="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  {{- end}}
</main>
</body>
</html>
`))

type loginProvider struct {
	Name string
	URL  string
}

type loginForm struct {
	Action string
	Token  string
}

type loginPageData struct {
	Providers []loginProvider
	Form      *loginForm
	Failure   bool
}

// renderLoginPage writes the chooser and credential form for the
// extension's interactive providers; `jwt` never appears
// (docs/spec/authentication.md Login page).
func (e *Enforcer) renderLoginPage(w http.ResponseWriter, formToken string) int {
	return e.renderLoginPageResult(w, formToken, false)
}

func (e *Enforcer) renderLoginPageResult(
	w http.ResponseWriter,
	formToken string,
	failure bool,
) int {
	data := loginPageData{Failure: failure}

	if e.cfg.OIDC != nil {
		data.Providers = append(data.Providers, loginProvider{
			Name: displayName(e.cfg.OIDC.DisplayName, "OpenID Connect"),
			URL:  e.startURL("oidc"),
		})
	}

	if e.cfg.SAML != nil {
		data.Providers = append(data.Providers, loginProvider{
			Name: displayName(e.cfg.SAML.DisplayName, "SAML"),
			URL:  e.startURL("saml"),
		})
	}

	if e.cfg.LDAP != nil {
		data.Form = &loginForm{
			Action: e.cfg.PathPrefix + "/ldap/login",
			Token:  formToken,
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	status := http.StatusOK
	if failure {
		status = http.StatusUnauthorized
	}

	w.WriteHeader(status)

	if err := loginPage.Execute(w, data); err != nil {
		return http.StatusInternalServerError
	}

	return status
}

func displayName(configured, fallback string) string {
	if configured != "" {
		return configured
	}

	return fallback
}
