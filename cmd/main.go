// Package main contains an example identity provider implementation.
package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"net/url"
	"path/filepath"

	"github.com/crewjam/saml/logger"
	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/securecookie"
	"github.com/pgstenberg/saml2-oidc-proxy/internal/pkg/config"
	"github.com/pgstenberg/saml2-oidc-proxy/internal/pkg/idp"
	"github.com/zenazn/goji"
)

type User struct {
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

func main() {

	var cfg config.Config

	configFile := flag.String("config", "", "Configuration file to be used.")
	scriptFile := flag.String("script", "", "Script file to be used.")
	serviceProvidersGlob := flag.String("serviceproviders", "./*.xml", "GLOB for where to find seviceprovide configuration(s).")

	flag.Parse()

	if configFile != nil {
		config.ReadYaml(&cfg, *configFile)
	}
	config.ReadEnv(&cfg)

	logr := logger.DefaultLogger

	baseURL, err := url.Parse(cfg.Saml2IdentityProvider.BaseUrl)
	if err != nil {
		logr.Fatalf("cannot parse base URL: %v", err)
	}

	key := func() crypto.PrivateKey {
		b, _ := pem.Decode([]byte(cfg.Saml2IdentityProvider.PrivateKey))
		k, _ := x509.ParsePKCS1PrivateKey(b.Bytes)
		return k
	}()
	cert := func() *x509.Certificate {
		b, _ := pem.Decode([]byte(cfg.Saml2IdentityProvider.Certificate))
		c, _ := x509.ParseCertificate(b.Bytes)
		return c
	}()

	// Skip SSL check
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	sc := securecookie.New([]byte(cfg.Saml2IdentityProvider.CookieHashKey), []byte(cfg.Saml2IdentityProvider.CookieEncryptionKey))

	idpServer, err := idp.NewServer(
		*baseURL,
		cfg.Saml2IdentityProvider.MetadataPath,
		cfg.Saml2IdentityProvider.SsoPath,
		logr,
		key,
		nil,
		cert,
		cfg.OpenIdConnectClient.Issuer,
		cfg.OpenIdConnectClient.ClientId,
		cfg.OpenIdConnectClient.ClientSecret,
		sc,
		scriptFile,
		serviceProvidersGlob,
	)

	if err != nil {
		logr.Fatalf("%s", err)
	}

	idpServer.ReloadScript()
	idpServer.ReloadServiceProviders()

	// Create new watcher.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	// Start listening for events.
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Script file was updated.
				if event.Has(fsnotify.Write) {
					if event.Name == *scriptFile {
						idpServer.ReloadScript()
					}
				}
				// Any service providers was updated or created.
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if match, _ := filepath.Match(*serviceProvidersGlob, event.Name); match {
						idpServer.ReloadServiceProviders()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logr.Println(err)
			}
		}
	}()

	// Add a path.
	if err = watcher.Add("."); err != nil {
		logr.Fatalln(err)
	}

	goji.Handle("/*", idpServer)
	goji.Serve()

}
