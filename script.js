/*
SCRIPT FOR OUTBOUND TRAFFIC (FROM OIDC PROVIDER)
*/
function outbound(context) {
  const STANDARD_OIDC_CLAIMS = [
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
  return {
    attributes: Object.keys(context.claims)
      .filter(key => !STANDARD_OIDC_CLAIMS.includes(key))
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
function inbound(context) {

  console.log("HELLO WORLD!");

  if(context.forceAuthn){
    return {
      prompt: 'login'
    }
  }

  return {}
}