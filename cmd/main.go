// Package main contains an example identity provider implementation.
package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"net/http"
	"net/url"

	"github.com/crewjam/saml/logger"
	"github.com/gorilla/securecookie"
	"github.com/pgstenberg/saml2-oidc-proxy/internal/pkg/idp"
	"github.com/zenazn/goji"
)

type User struct {
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
}

func main() {

	/*
		user := &User{
			Name: "test321321",
			Attributes: map[string]string{
				"test1": "abc",
				"test2": "fafda",
			},
		}

		const SCRIPT = `
		function test(user) {
			return user.attributes["test1"];
		}
		`

		vm := goja.New()
		vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", false))
		_, err := vm.RunString(SCRIPT)
		if err != nil {
			panic(err)
		}
		test, ok := goja.AssertFunction(vm.Get("test"))
		if !ok {
			panic("Not a function")
		}

		res, err := test(goja.Undefined(), vm.ToValue(user))
		if err != nil {
			panic(err)
		}
		fmt.Println(res)
	*/

	var cfg idp.Config

	configFile := flag.String("config", "", "Configuration file to be used.")
	flag.Parse()
	if *configFile != "" {
		idp.ReadYaml(&cfg, *configFile)
	}

	idp.ReadEnv(&cfg)

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
		cfg.Server.Script,
	)

	if err != nil {
		logr.Fatalf("%s", err)
	}

	goji.Handle("/*", idpServer)
	goji.Serve()

}
