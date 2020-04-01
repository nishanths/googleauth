package main

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/datastore"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	ds, err := datastore.NewClient(ctx, os.Getenv("GOOGLE_CLOUD_PROJECT"))
	if err != nil {
		return fmt.Errorf("datastore client: %s", err)
	}
	defer ds.Close()

	s, err := newService(ctx, ds)
	if err != nil {
		return fmt.Errorf("creating service: %s", err)
	}

	http.Handle("/", withHTTPS(http.HandlerFunc(s.indexHandler)))
	http.Handle("/login", withHTTPS(http.HandlerFunc(s.loginHandler)))
	http.Handle("/auth", withHTTPS(http.HandlerFunc(s.authHandler)))
	http.Handle("/logout", withHTTPS(http.HandlerFunc(s.logoutHandler)))
	http.Handle("/me", withHTTPS(http.HandlerFunc(s.meHandler)))

	if err := http.ListenAndServe(":"+port, nil); err != nil {
		return fmt.Errorf("ListenAndServe: %s", err)
	}

	panic("should not be reachable")
}

type service struct {
	ds     *datastore.Client
	secret Secret
}

func newService(ctx context.Context, ds *datastore.Client) (*service, error) {
	var secret Secret
	if err := ds.Get(ctx, datastore.NameKey("Secret", "singleton", nil), &secret); err != nil {
		return nil, fmt.Errorf("failed to get secret: %s", err)
	}
	return &service{
		ds:     ds,
		secret: secret,
	}, nil
}

// Secret is the Go type for the Secret entity in Datastore.
type Secret struct {
	CookieHashKey      string
	CookieBlockKey     string
	GoogleClientID     string
	GoogleClientSecret string
}

func withHTTPS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if maybeRedirectHTTPS(w, r) {
			return
		}
		h.ServeHTTP(w, r)
	})
}

// Redirect requests with a "http" scheme to "https", unless
// running in local dev.
func maybeRedirectHTTPS(w http.ResponseWriter, r *http.Request) bool {
	if isDev() {
		return false
	}
	u := *r.URL
	if u.Scheme != "http" {
		return false
	}
	u.Scheme = "https"
	http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	return true
}

func isDev() bool {
	return os.Getenv("GAE_DEPLOYMENT_ID") == ""
}

func drainAndClose(r io.ReadCloser) {
	io.Copy(ioutil.Discard, r)
	r.Close()
}
