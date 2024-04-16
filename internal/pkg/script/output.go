package script

type UpstreamOutput struct {
	AcrValues *[]string
	Prompt    *string
}
type DownstreamOutput struct {
	Attributes map[string]interface{}
	NameID     interface{}
}

func createDownstreamOutput(obj map[string]interface{}) *DownstreamOutput {
	return &DownstreamOutput{
		Attributes: obj["attributes"].(map[string]interface{}),
		NameID:     obj["nameID"].(string),
	}
}
func createUpstreamOutput(obj map[string]interface{}) *UpstreamOutput {
	output := &UpstreamOutput{}

	if acrValues, ok := obj["acrValues"]; ok {
		if acrValues != nil {
			v := acrValues.([]string)
			output.AcrValues = &v
		}
	}
	if prompt, ok := obj["prompt"]; ok {
		if prompt != nil {
			v := prompt.(string)
			output.Prompt = &v
		}
	}

	return output
}
