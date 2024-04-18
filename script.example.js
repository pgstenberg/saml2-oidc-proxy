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