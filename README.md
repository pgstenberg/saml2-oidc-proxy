# Simple SAML2 to OIDC Proxy

Simple, lightweight and scriptable SAML2 to OIDC Proxy writting in go-lang.
Heavily based on;

* [crewjam/saml](github.com/crewjam/saml) - SAML2 IdP implementation using go-lang for handling SAML2 authentication-requests.
* [coreos/go-oidc](github.com/coreos/go-oidc) - OpenID Connection Client Go implementation for the external federation.
* [dop251/goja](github.com/dop251/goja) - Pure Go ECMAScript engine used for processing of upstream and downstream requests using configurable scripts.

## Motivation

OpenID Connect is the facto new standard for decentralized authentication and federation, however, SAML2 is still widly used, especially within B2B or B2E settings with highly regulated businesses and agencies.
The idea is to use this application as a supplementary service for your more centralized OpenID Connect IdP to cover just these type of use-cases without introducing uncessary complexity in your IdP.

## Installation

Easiest way to run this application is through Docker. A `Dockerfile` is provided in the repository and can be used to build a very minimal container with the necessary binary.

```bash
# Build a new Docker Image
docker build --tag pgstenberg/saml2-oidc-proxy .
# Run the image
docker run pgstenberg/saml2-oidc-proxy -help
Usage of /bin/saml2-oidc-proxy:
  -bind string
        Address to bind on. If this value has a colon, as in ":8000" or
                        "127.0.0.1:9001", it will be treated as a TCP address. If it
                        begins with a "/" or a ".", it will be treated as a path to a
                        UNIX socket. If it begins with the string "fd@", as in "fd@3",
                        it will be treated as a file descriptor (useful for use with
                        systemd, for instance). If it begins with the string "einhorn@",
                        as in "einhorn@0", the corresponding einhorn socket will be
                        used. If an option is not explicitly passed, the implementation
                        will automatically select among "einhorn@0" (Einhorn), "fd@3"
                        (systemd), and ":8000" (fallback) based on its environment. (default ":8000")
  -config string
        Configuration file to be used.
  -script string
        Script file to be used.
  -serviceproviders string
        GLOB for where to find seviceprovide configuration(s). (default "./*.xml")
```

## Configuration

Configuration can be done either by reading configuration through a dedicated YAML file or by passing environment variables to the application. These can be interchanged, meaning some values can be in the YAML file and some specified using environment variables.

### Setting up SAML2 SP trust

Service provide(s) can be configured by putting the service providers metadata xml in a `.xml` file on the file-system.

These service-provider will be **reloaded in-runtime** if any glob match appear.

### Scripting

Custom scripting can be using specificed `.js` file, the file need to contain two functions; `upstream` and `downstream`.

```js
function downstream(context) {
  return {
    attributes: Object.keys(context.claims)
      .filter(key => !contex.getStandardClaims().includes(key))
      .reduce((obj, key) => {
        obj[key] = context.claims[key];
        return obj;
      }, {}),
      nameID: context.claims.sub
  }
}
function upstream(context) {
  return {
    prompt: (context.forceAuthn) ? "login"undefined
  }
}
```

This configuration will be **reloaded in-runtime** once a change is done in the specified `.js` file.
