package idp

const DEFAULT_SCRIPT string = `
/*
SCRIPT FOR OUTBOUND TRAFFIC (FROM OIDC PROVIDER)
*/
function upstream(context) {

  return {
      attributes: Object.keys(context.claims)
          .filter(key => !GetStandardClaims().includes(key))
          .reduce((obj, key) => {
            obj[key] = context.claims[key];
            return obj;
          }, {}),
      nameID: context.claims.sub
  }
}

/*
SCRIPT FOR INBOUND TRAFFIC (FROM SAML2 CLIENT)
*/
function downstream(context) {

  if(context.forceAuthn){
      return {
          prompt: 'login'
      }
  }

  return {}
}
`

const GLOBALS string = `
function GetStandardClaims() {
	return [
      'iss', 
      'sub',
      'aud',
      'exp',
      'iat',
      'auth_time',
      'nonce',
      'acr',
      'amr',
      'azp'
  	];
}
`
