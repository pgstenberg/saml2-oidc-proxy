package idp

import (
	"github.com/crewjam/saml/logger"
	"github.com/dop251/goja"
)

type ScriptRuntime struct {
	vm               *goja.Runtime
	script           *string
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
	AcrValues *[]string
	Prompt    *string
}
type InboundContext struct {
	AcrContext string
	ForceAuthn bool
}
type OutboundOutput struct {
	Attributes map[string]interface{}
	NameID     interface{}
}
type OutboundContext struct {
	Claims map[string]interface{}
}

func NewScriptRuntime(logger logger.Interface) (*ScriptRuntime, error) {

	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())

	c := newConsole(vm, logger)
	vm.Set("console", c)

	script := &ScriptRuntime{
		vm: vm,
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
		NameID:     obj["nameID"].(string),
	}, nil
}
func (runtime *ScriptRuntime) ProcessInbound(input *InboundContext) (*InboundOutput, error) {

	res, err := runtime.inboundFunction(goja.Undefined(), runtime.vm.ToValue(input))
	if err != nil {
		return nil, err
	}
	obj := res.Export().(map[string]interface{})

	output := &InboundOutput{}

	if acrValues, ok := obj["acrValues"]; ok {
		v := acrValues.([]string)
		output.AcrValues = &v
	}
	if prompt, ok := obj["prompt"]; ok {
		v := prompt.(string)
		output.Prompt = &v
	}

	return output, nil
}
