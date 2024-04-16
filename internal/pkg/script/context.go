package script

type Context interface {
	GetStandardClaims() []string
}
type AbtractContext struct {
	Context
}
type UpstreamContext struct {
	*AbtractContext
	AcrContext string
	EntityID   string
	ForceAuthn bool
}
type DownstreamContext struct {
	*AbtractContext
	Claims map[string]interface{}
}

func (c *AbtractContext) GetStandardClaims() []string {
	return []string{
		"iss",
		"sub",
		"aud",
		"exp",
		"iat",
		"auth_time",
		"nonce",
		"acr",
		"amr",
		"azp",
	}
}

func NewUpstreamContext() *UpstreamContext {
	c := &AbtractContext{}
	uc := &UpstreamContext{}
	c.Context = uc
	return uc
}
func NewDownstreamContext() *DownstreamContext {
	c := &AbtractContext{}
	dc := &DownstreamContext{}
	c.Context = dc
	return dc
}
