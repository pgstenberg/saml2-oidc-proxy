package idp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

type Server struct {
	http.Handler
	idpConfigMu      sync.RWMutex // protects calls into the IDP
	serviceProviders map[string]*saml.EntityDescriptor
	Idp              saml.IdentityProvider // the underlying IDP
	oauth2Config     oauth2.Config
	oidcProvider     *oidc.Provider
	secureCookie     *securecookie.SecureCookie
	logger           logger.Interface
}

func New(
	baseUrl url.URL,
	metadataPath string,
	ssoPath string,
	logger logger.Interface,
	key crypto.PrivateKey,
	signer crypto.Signer,
	certificate *x509.Certificate,
	oidcIssuer string,
	oidcClient string,
	oidcClientSecret string,
	secureCookie *securecookie.SecureCookie,
) (*Server, error) {

	if len(metadataPath) == 0 {
		metadataPath = "/metadata"
	}
	if len(ssoPath) == 0 {
		ssoPath = "/sso"
	}

	metadataURL := baseUrl
	metadataURL.Path += metadataPath
	ssoURL := baseUrl
	ssoURL.Path += ssoPath

	oidcProvider, err := oidc.NewProvider(context.Background(), oidcIssuer)
	if err != nil {
		return nil, err
	}

	server := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		Idp: saml.IdentityProvider{
			Key:         key,
			Signer:      signer,
			Logger:      logger,
			Certificate: certificate,
			MetadataURL: metadataURL,
			SSOURL:      ssoURL,
		},
		oauth2Config: oauth2.Config{
			ClientID:     oidcClient,
			ClientSecret: oidcClientSecret,
			RedirectURL:  baseUrl.String() + "/oauth/v2/callback",

			// Discovery returns the OAuth2 endpoints.
			Endpoint: oidcProvider.Endpoint(),

			// "openid" is a required scope for OpenID Connect flows.
			Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
		},
		oidcProvider: oidcProvider,
		secureCookie: secureCookie,
		logger:       logger,
	}

	server.Idp.SessionProvider = server
	server.Idp.ServiceProviderProvider = server

	server.loadServiceProviders()

	/**
	    WEBSERVICE
	**/
	mux := web.New()
	server.Handler = mux

	mux.Get(metadataPath, func(w http.ResponseWriter, r *http.Request) {
		server.idpConfigMu.RLock()
		defer server.idpConfigMu.RUnlock()
		server.Idp.ServeMetadata(w, r)
	})
	mux.Handle(ssoPath, func(w http.ResponseWriter, r *http.Request) {
		server.idpConfigMu.RLock()
		defer server.idpConfigMu.RUnlock()
		server.Idp.ServeSSO(w, r)
	})
	mux.Handle("/oauth/v2/callback", func(w http.ResponseWriter, r *http.Request) {
		server.idpConfigMu.RLock()
		defer server.idpConfigMu.RUnlock()
		handleOAuth2Callback(server, w, r)
	})

	server.logger.Println("SP loaded=%s", server.serviceProviders)

	return server, nil
}

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

func (server *Server) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {

	if _, err := r.Cookie("_authn"); err != nil {

		state := uuid.New().String()

		value := map[string]string{
			"state":       state,
			"SAMLRequest": r.URL.Query().Get("SAMLRequest"),
		}

		if encoded, err := server.secureCookie.Encode("_session", value); err == nil {
			cookie := &http.Cookie{
				Name:     "_session",
				Value:    encoded,
				Path:     "/",
				Secure:   true,
				HttpOnly: true,
			}
			http.SetCookie(w, cookie)
			http.Redirect(w, r, server.oauth2Config.AuthCodeURL(state), http.StatusFound)
			return nil
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	if cookie, err := r.Cookie("_authn"); err == nil {

		value := make(map[string]string)
		if err = server.secureCookie.Decode("_authn", cookie.Value, &value); err == nil {

			server.logger.Println("Trying to parse and validate id_token=%s", value["id_token"])

			// Parse and verify ID Token payload.
			idToken, err := server.oidcProvider.Verifier(&oidc.Config{ClientID: server.oauth2Config.ClientID}).Verify(r.Context(), value["id_token"])

			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}

			// Extract custom claims
			var claims struct {
				Subject  string `json:"sub"`
				Email    string `json:"email"`
				Verified bool   `json:"email_verified"`
			}
			if err := idToken.Claims(&claims); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
			}

			session := &saml.Session{
				ID:         base64.StdEncoding.EncodeToString(randomBytes(32)),
				CreateTime: saml.TimeNow(),
				ExpireTime: saml.TimeNow().Add(time.Hour),
				Index:      hex.EncodeToString(randomBytes(32)),
				NameID:     claims.Subject,
				/*
				   Groups:                []string{"group01", "group02"},
				   UserEmail:             "test@test.com",
				   UserCommonName:        "UserCommonName",
				   UserSurname:           "UserSurname",
				   UserGivenName:         "UserGivenName",
				   UserScopedAffiliation: "UserScopedAffiliation",
				*/
			}

			// Remove session cookie
			http.SetCookie(w, &http.Cookie{
				Name:    "_session",
				Value:   "",
				Path:    "/",
				Expires: time.Unix(0, 0),

				HttpOnly: true,
			})
			// Remove authn cookie
			http.SetCookie(w, &http.Cookie{
				Name:    "_authn",
				Value:   "",
				Path:    "/",
				Expires: time.Unix(0, 0),

				HttpOnly: true,
			})

			return session
		}
	}

	return nil

}

func (server *Server) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	server.idpConfigMu.RLock()
	defer server.idpConfigMu.RUnlock()
	rv, ok := server.serviceProviders[serviceProviderID]
	if !ok {
		return nil, os.ErrNotExist
	}
	return rv, nil
}

func handleOAuth2Callback(server *Server, w http.ResponseWriter, r *http.Request) {

	if cookie, err := r.Cookie("_session"); err == nil {

		value := make(map[string]string)

		if err = server.secureCookie.Decode("_session", cookie.Value, &value); err == nil {
			samlRequest := url.QueryEscape(value["SAMLRequest"])
			state := value["state"]

			server.logger.Println("SAMLRequest=%s, state=%s", samlRequest, state)

			if r.URL.Query().Get("state") != state {
				server.logger.Println("state=%s, did not match state=%s", state, r.URL.Query().Get("state"))
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}

			oauth2Token, err := server.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
			if err != nil {
				server.logger.Println(err.Error())
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				server.logger.Println("Invalid id_token")
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}

			value := map[string]string{
				"id_token": rawIDToken,
			}
			if encoded, err := server.secureCookie.Encode("_authn", value); err == nil {
				cookie := &http.Cookie{
					Name:     "_authn",
					Value:    encoded,
					Path:     "/",
					Secure:   true,
					HttpOnly: true,
				}
				http.SetCookie(w, cookie)
				http.Redirect(w, r, "/sso?SAMLRequest="+samlRequest, http.StatusFound)
				return
			}

		}
	}

	http.Error(w, "Internal Server Error", http.StatusInternalServerError)

}

func (server *Server) loadServiceProviders() {
	pattern := "*.xml"
	files, err := filepath.Glob(pattern)
	if err != nil {
		server.logger.Fatalln(err)
		return
	}
	server.logger.Println("Found SP configuration=%s", files)

	for _, f := range files {
		reader, err := os.Open(f)

		if err != nil {
			server.logger.Fatalln(err)
			return
		}

		metadata, err := getSPMetadata(reader)
		if err != nil {
			server.logger.Fatalln(err)
			return
		}

		server.idpConfigMu.Lock()
		server.serviceProviders[metadata.EntityID] = metadata
		server.idpConfigMu.Unlock()

		reader.Close()
	}

}

func getSPMetadata(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
	var data []byte
	if data, err = io.ReadAll(r); err != nil {
		return nil, err
	}

	spMetadata = &saml.EntityDescriptor{}
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	if err := xml.Unmarshal(data, &spMetadata); err != nil {
		if err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}
			if err := xml.Unmarshal(data, &entities); err != nil {
				return nil, err
			}

			for _, e := range entities.EntityDescriptors {
				if len(e.SPSSODescriptors) > 0 {
					return &e, nil
				}
			}

			// there were no SPSSODescriptors in the response
			return nil, errors.New("metadata contained no service provider metadata")
		}

		return nil, err
	}

	return spMetadata, nil
}
