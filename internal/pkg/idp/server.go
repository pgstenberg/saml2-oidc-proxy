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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
	"github.com/google/uuid"
	"github.com/gorilla/securecookie"
	"github.com/pgstenberg/saml2-oidc-proxy/internal/pkg/script"
	"github.com/zenazn/goji/web"
	"golang.org/x/oauth2"

	xrv "github.com/mattermost/xml-roundtrip-validator"
)

type Server struct {
	http.Handler
	idpConfigMu          sync.RWMutex // protects calls into the IDP
	serviceProviders     map[string]*saml.EntityDescriptor
	Idp                  saml.IdentityProvider // the underlying IDP
	oauth2Config         oauth2.Config
	oidcProvider         *oidc.Provider
	secureCookie         *securecookie.SecureCookie
	logger               logger.Interface
	scriptRuntime        *script.Runtime
	scriptFile           *string
	serviceProvidersGlob *string
}

func NewServer(
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
	scriptFile *string,
	serviceProvidersGlob *string,
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

	scriptRuntime, err := script.NewRuntime(logger)
	if err != nil {
		return nil, err
	}

	server := &Server{
		serviceProviders: map[string]*saml.EntityDescriptor{},
		Idp: saml.IdentityProvider{
			Key:            key,
			Signer:         signer,
			Logger:         logger,
			Certificate:    certificate,
			MetadataURL:    metadataURL,
			SSOURL:         ssoURL,
			AssertionMaker: OpenIdConnectAssertionMaker{},
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
		oidcProvider:         oidcProvider,
		secureCookie:         secureCookie,
		logger:               logger,
		scriptRuntime:        scriptRuntime,
		scriptFile:           scriptFile,
		serviceProvidersGlob: serviceProvidersGlob,
	}

	server.Idp.SessionProvider = server
	server.Idp.ServiceProviderProvider = server

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
		serveCallback(server, w, r)
	})

	return server, nil
}

func clearCookies(w http.ResponseWriter) {
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
}

const (
	HttpMessageInternalServerError = "INTERNAL_SERVER_ERROR"
	httpMessageFederationFailed    = "FEDERATION_FAILED"
)

func httpError(msg string, errorType int, err error, w http.ResponseWriter, lgr logger.Interface) {
	lgr.Println(err.Error())
	http.Error(w, msg, errorType)
}

func (server *Server) GetSession(w http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {

	UpstreamContext := func() *script.UpstreamContext {
		context := script.NewUpstreamContext()

		context.AcrContext = req.Request.RequestedAuthnContext.AuthnContextClassRef

		if req.Request.ForceAuthn != nil {
			context.ForceAuthn = *req.Request.ForceAuthn
		}
		context.EntityID = req.ServiceProviderMetadata.EntityID

		return context
	}

	DownstreamContext := func(claims map[string]interface{}) *script.DownstreamContext {
		context := script.NewDownstreamContext()

		context.Claims = claims

		return context
	}

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

			output, err := server.scriptRuntime.ProcessUpstream(UpstreamContext())
			if err != nil {
				clearCookies(w)
				httpError(HttpMessageInternalServerError, http.StatusInternalServerError, err, w, server.logger)
			}

			opts := []oauth2.AuthCodeOption{}
			if output.AcrValues != nil {
				opts = append(opts, oauth2.SetAuthURLParam("acr_values", strings.Join(*output.AcrValues, " ")))
			}
			if output.Prompt != nil {
				opts = append(opts, oauth2.SetAuthURLParam("prompt", *output.Prompt))
			}

			http.Redirect(w, r, server.oauth2Config.AuthCodeURL(state, opts...), http.StatusFound)
			return nil
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	if cookie, err := r.Cookie("_authn"); err == nil {

		value := make(map[string]string)
		if err = server.secureCookie.Decode("_authn", cookie.Value, &value); err == nil {

			server.logger.Printf("Trying to parse and validate id_token=%s", value["id_token"])

			// Parse and verify ID Token payload.
			idToken, err := server.oidcProvider.Verifier(&oidc.Config{ClientID: server.oauth2Config.ClientID}).Verify(r.Context(), value["id_token"])

			if err != nil {
				clearCookies(w)
				httpError(httpMessageFederationFailed, http.StatusBadRequest, err, w, server.logger)
			}

			// Extract custom claims
			var claims map[string]interface{}
			if err := idToken.Claims(&claims); err != nil {
				clearCookies(w)
				httpError(httpMessageFederationFailed, http.StatusBadRequest, err, w, server.logger)
			}

			output, err := server.scriptRuntime.ProcessDownstream(DownstreamContext(claims))
			if err != nil {
				clearCookies(w)
				httpError(HttpMessageInternalServerError, http.StatusInternalServerError, err, w, server.logger)
			}

			attributes := []saml.Attribute{}

			for idx, attr := range output.Attributes {
				switch v := attr.(type) {
				case string:
					attributes = append(attributes, saml.Attribute{
						Name: idx,
						Values: []saml.AttributeValue{{
							Type:  "xs:string",
							Value: v,
						}},
					})
				case float64:
					attributes = append(attributes, saml.Attribute{
						Name: idx,
						Values: []saml.AttributeValue{{
							Type:  "xs:integer",
							Value: fmt.Sprintf("%f", v),
						}},
					})
				default:
					// t is some other type that we didn't name.
				}
			}

			session := &saml.Session{
				ID:               base64.StdEncoding.EncodeToString(randomBytes(32)),
				CreateTime:       saml.TimeNow(),
				ExpireTime:       saml.TimeNow().Add(time.Hour),
				Index:            hex.EncodeToString(randomBytes(32)),
				NameID:           output.NameID.(string),
				CustomAttributes: attributes,
			}

			clearCookies(w)

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

func serveCallback(server *Server, w http.ResponseWriter, r *http.Request) {

	if cookie, err := r.Cookie("_session"); err == nil {

		value := make(map[string]string)

		if err = server.secureCookie.Decode("_session", cookie.Value, &value); err == nil {
			samlRequest := url.QueryEscape(value["SAMLRequest"])
			state := value["state"]

			server.logger.Println("SAMLRequest=%s, state=%s", samlRequest, state)

			if r.URL.Query().Get("state") != state {
				clearCookies(w)
				httpError(httpMessageFederationFailed, http.StatusBadRequest, fmt.Errorf("state=%s, did not match state=%s", state, r.URL.Query().Get("state")), w, server.logger)
			}

			oauth2Token, err := server.oauth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
			if err != nil {
				clearCookies(w)
				httpError(httpMessageFederationFailed, http.StatusBadRequest, err, w, server.logger)
			}

			// Extract the ID Token from OAuth2 token.
			rawIDToken, ok := oauth2Token.Extra("id_token").(string)
			if !ok {
				clearCookies(w)
				httpError(httpMessageFederationFailed, http.StatusBadRequest, fmt.Errorf("invalid id_token"), w, server.logger)
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

	clearCookies(w)
	httpError(httpMessageFederationFailed, http.StatusBadRequest, fmt.Errorf("no _session cookie found"), w, server.logger)

}

func (server *Server) ReloadScript() {

	// Default Script
	var scriptContent string = `
		function downstream(context) {
			return {
				attributes: Object.keys(context.claims)
					.filter(key => !context.getStandardClaims().includes(key))
					.reduce((obj, key) => {
						obj[key] = context.claims[key];
						return obj;
					}, {}),
				nameID: context.claims.sub
			}
		}
		function upstream(context) {
			return {
				prompt: (context.forceAuthn) ? "login": undefined
			}
		}
	`

	// Load script from file if not nil
	if server.scriptFile != nil && *server.scriptFile != "" {
		f, err := os.ReadFile(*server.scriptFile)
		if err != nil {
			server.logger.Panicln(err)
			return
		}
		scriptContent = string(f)
	}

	server.idpConfigMu.Lock()
	if err := server.scriptRuntime.LoadScript(scriptContent); err != nil {
		server.logger.Println(err)
	}
	server.idpConfigMu.Unlock()

	server.logger.Println("Script successfully loaded:\n" + scriptContent)
}

func (server *Server) ReloadServiceProviders() {
	files, err := filepath.Glob(*server.serviceProvidersGlob)
	if err != nil {
		server.logger.Fatalln(err)
		return
	}

	metadata := func(r io.Reader) (spMetadata *saml.EntityDescriptor, err error) {
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

	for _, f := range files {
		reader, err := os.Open(f)

		if err != nil {
			server.logger.Println(err)
			return
		}

		metadata, err := metadata(reader)

		if err != nil {
			server.logger.Println(err)
			return
		}

		server.idpConfigMu.Lock()
		server.serviceProviders[metadata.EntityID] = metadata
		server.idpConfigMu.Unlock()

		reader.Close()

		server.logger.Printf("Successfully loaded; file=%s, entityid=%s", files, metadata.EntityID)
	}

}
