package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"
)

const addr = "127.0.0.2:443"

const cookieDomain = ".auth.test"

const githubForm = `<!DOCTYPE html>
<html>
<head><title>Sign in to AuthHub</title></head>
<body>
  <h1>Sign in to AuthHub</h1>
  <form method="post" action="/login">
    <input type="text" name="login" placeholder="Username" required autofocus>
    <input type="password" name="password" placeholder="Password" required>
    <button type="submit">Sign in</button>
  </form>
  <p><a href="/login">Sign in</a> &middot; <a href="https://www.auth.test/login">Absolute link (tests sub_filters)</a></p>
</body>
</html>`

const liveForm = `<!DOCTYPE html>
<html>
<head><title>Sign in to your account</title></head>
<body>
  <h1>Sign in to your account</h1>
  <form method="post" action="/login">
    <input type="email" name="loginfmt" placeholder="Email, phone, or Skype" required autofocus>
    <input type="password" name="passwd" placeholder="Password" required>
    <input type="checkbox" name="Kmsi" value="1"> <label>Keep me signed in</label>
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`

const dashPage = `<!DOCTYPE html>
<html>
<head><title>Dashboard</title></head>
<body>
  <h1>Welcome, {{.User}}</h1>
  <p>You are signed in as {{.User}} ({{.Style}}).</p>
  <p><a href="/logout">Sign out</a></p>
</body>
</html>`

func main() {
	tlsCert, err := genSelfSignedCert()
	if err != nil {
		log.Fatal("cert: ", err)
	}

	srv := &http.Server{
		Addr:      addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		Handler:   http.HandlerFunc(handle),
	}

	log.Printf("mock auth site listening on https://%s", addr)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		log.Fatal("listen: ", err)
	}
}

func handle(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	style := "github"
	if strings.HasPrefix(host, "login.") {
		style = "live"
	}

	log.Printf("%s %s from %s (host: %s)", r.Method, r.URL.Path, r.RemoteAddr, host)

	switch r.URL.Path {
	case "/", "/index.html":
		http.Redirect(w, r, "/login", http.StatusFound)
	case "/login":
		switch r.Method {
		case http.MethodGet:
			body := githubForm
			if style == "live" {
				body = liveForm
			}
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, body)
		case http.MethodPost:
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if style == "live" {
				user := r.Form.Get("loginfmt")
				pass := r.Form.Get("passwd")
				setCookie(w, "ESTSAUTH", randToken(), true)
				setCookie(w, "ESTSAUTHPERSISTENT", randToken(), true)
				setCookie(w, "ULCfg", "1", false)
				setCookie(w, "esctx", randToken(), true)
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				log.Printf("LOGIN(live) user=%q pass=%q", user, pass)
			} else {
				user := r.Form.Get("login")
				pass := r.Form.Get("password")
				setCookie(w, "user_session", randToken(), true)
				setCookie(w, "logged_in", "yes", false)
				setCookie(w, "dotcom_user", user, false)
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				log.Printf("LOGIN(github) user=%q pass=%q", user, pass)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/dashboard":
		user := getCookie(r, "dotcom_user")
		if user == "" {
			user = getCookie(r, "ESTSAUTHPERSISTENT")
			if user != "" {
				user = "microsoft-user"
			}
		}
		if user == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		t := template.Must(template.New("dash").Parse(dashPage))
		t.Execute(w, struct{ User, Style string }{user, style})
	case "/bfp":
		w.WriteHeader(http.StatusNoContent)
	case "/logout":
		for _, n := range []string{"user_session", "logged_in", "dotcom_user", "ESTSAUTH", "ESTSAUTHPERSISTENT", "ULCfg", "esctx"} {
			http.SetCookie(w, &http.Cookie{Name: n, Value: "", Domain: cookieDomain, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func setCookie(w http.ResponseWriter, name, value string, httpOnly bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Domain:   cookieDomain,
		Path:     "/",
		Secure:   true,
		HttpOnly: httpOnly,
		SameSite: http.SameSiteNoneMode,
	})
}

func getCookie(r *http.Request, name string) string {
	if c, err := r.Cookie(name); err == nil {
		return c.Value
	}
	return ""
}

func randToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func genSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Mock Auth Site"}, CommonName: "auth.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"auth.test", "www.auth.test", "login.auth.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
