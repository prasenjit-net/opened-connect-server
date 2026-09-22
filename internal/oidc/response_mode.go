package oidc

import (
	"html/template"
	"net/http"
	"net/url"
)

const responseModeFormPost = "form_post"

func validCodeResponseMode(mode string) bool {
	return mode == "" || mode == "query" || mode == responseModeFormPost
}

func writeFormPost(w http.ResponseWriter, action string, responseURL string) {
	u, err := url.Parse(responseURL)
	if err != nil {
		writeAuthorizeErrorPage(w, "Unable to deliver the authorization response.")
		return
	}
	actionURL, err := url.Parse(action)
	if err != nil {
		writeAuthorizeErrorPage(w, "Unable to deliver the authorization response.")
		return
	}
	values := u.Query()
	for name := range actionURL.Query() {
		values.Del(name)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; form-action "+action)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = template.Must(template.New("form_post").Parse(`<!doctype html><html><head><meta charset="utf-8"><title>Continue</title></head><body onload="document.forms[0].submit()"><form method="post" action="{{.Action}}">{{range .Values}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">{{end}}<button type="submit">Continue</button></form></body></html>`)).Execute(w, struct {
		Action string
		Values []struct{ Name, Value string }
	}{action, valuesForForm(values)})
}

func valuesForForm(values url.Values) []struct{ Name, Value string } {
	out := []struct{ Name, Value string }{}
	for name, values := range values {
		for _, value := range values {
			out = append(out, struct{ Name, Value string }{name, value})
		}
	}
	return out
}
