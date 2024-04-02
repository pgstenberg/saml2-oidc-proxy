package idp

import (
	"github.com/crewjam/saml/logger"
	"github.com/dop251/goja"
)

type ScriptRuntime struct {
	vm               *goja.Runtime
	outboundFunction goja.Callable
	inboundFunction  goja.Callable
}

type console struct {
	logger logger.Interface
}

func (c *console) log(msg string) {
	c.logger.Println(msg)
}
func newConsole(vm *goja.Runtime, logger logger.Interface) *goja.Object {
	c := &console{
		logger: logger,
	}
	obj := vm.NewObject()
	obj.Set("log", c.log)
	return obj
}

type InboundOutput struct {
	AcrValues interface{} `json:"acr_values"`
	Prompt    interface{} `json:"prompt"`
}
type InboundContext struct {
	AcrContext string `json:"acr_context"`
	ForceAuthn bool   `json:"force_authn"`
}
type OutboundOutput struct {
	Attributes map[string]interface{} `json:"attributes"`
	NameID     string                 `json:"name_id"`
}
type OutboundContext struct {
	Claims map[string]interface{} `json:"claims"`
}

func NewScriptRuntime(scriptContent string, logger logger.Interface) (*ScriptRuntime, error) {

	vm := goja.New()
	vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", false))

	c := newConsole(vm, logger)
	vm.Set("console", c)

	_, err := vm.RunString(scriptContent)
	if err != nil {
		return nil, err
	}
	inboundFunction, ok := goja.AssertFunction(vm.Get("inbound"))
	if !ok {
		logger.Fatalln("inbound - Not a function")
	}
	outboundFunction, ok := goja.AssertFunction(vm.Get("outbound"))
	if !ok {
		logger.Fatalln("outbound - Not a function")
	}

	script := &ScriptRuntime{
		vm:               vm,
		outboundFunction: outboundFunction,
		inboundFunction:  inboundFunction,
	}

	return script, nil
}

func (runtime *ScriptRuntime) ProcessOutbound(input *OutboundContext) (*OutboundOutput, error) {

	res, err := runtime.outboundFunction(goja.Undefined(), runtime.vm.ToValue(input))
	if err != nil {
		return nil, err
	}

	obj := res.Export().(map[string]interface{})

	return &OutboundOutput{
		Attributes: obj["attributes"].(map[string]interface{}),
	}, nil
}
func (runtime *ScriptRuntime) ProcessInbound(input *InboundContext) (*InboundOutput, error) {

	res, err := runtime.inboundFunction(goja.Undefined(), runtime.vm.ToValue(input))
	if err != nil {
		return nil, err
	}

	obj := res.Export().(map[string]interface{})

	return &InboundOutput{
		AcrValues: obj["acr_values"],
		Prompt:    obj["prompt"],
	}, nil
}
