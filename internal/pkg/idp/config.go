package idp

import (
	"fmt"
	"os"

	"github.com/kelseyhightower/envconfig"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Saml2IdentityProvider struct {
		BaseUrl             string `yaml:"base_url", envconfig:"SAML2_IDP_BASE_URL"`
		SsoPath             string `yaml:"sso_path", envconfig:"SAML2_IDP_SSO_PATH"`
		MetadataPath        string `yaml:"metadata_path", envconfig:"SAML2_IDP_METADATA_PATH"`
		PrivateKey          string `yaml:"private_key", envconfig:"SAML2_IDP_PRIVATE_KEY"`
		Certificate         string `yaml:"certificate", envconfig:"SAML2_IDP_CERTIFICATE"`
		CookieHashKey       string `yaml:"cookie_hash_key", envconfig:"SAML2_IDP_COOKIE_HASH_KEY"`
		CookieEncryptionKey string `yaml:"cookie_encryption_key", envconfig:"SAML2_IDP_COOKIE_ENCRYPTION_KEY"`
	} `yaml:"saml2_identity_provider"`
	OpenIdConnectClient struct {
		Issuer       string `yaml:"issuer", envconfig:"OIDC_ISSUER"`
		ClientId     string `yaml:"client_id", envconfig:"OIDC_CLIENT_ID"`
		ClientSecret string `yaml:"client_secret", envconfig:"OIDC_CLIENT_SECRET"`
	} `yaml:"openid_connect_client"`
}

func ReadYaml(cfg *Config, filePath string) {
	f, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	defer f.Close()

	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(cfg); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}

func ReadEnv(cfg *Config) {
	if err := envconfig.Process("", cfg); err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
}
