package script

import (
	"errors"

	"github.com/crewjam/saml/logger"
	"github.com/dop251/goja"
)

type Runtime struct {
	vm                 *goja.Runtime
	downstreamFunction goja.Callable
	upstreamFunction   goja.Callable
	script             *string
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

type UpstreamOutput struct {
	AcrValues *[]string
	Prompt    *string
}
type UpstreamContext struct {
	AcrContext string
	ForceAuthn bool
}
type DownstreamOutput struct {
	Attributes map[string]interface{}
	NameID     interface{}
}
type DownstreamContext struct {
	Claims map[string]interface{}
}

func NewRuntime(logger logger.Interface) (*Runtime, error) {

	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())

	c := newConsole(vm, logger)
	vm.Set("console", c)

	script := &Runtime{
		vm: vm,
	}

	return script, nil
}

func (runtime *Runtime) LoadScript(script string) error {
	previousScript := &script

	loadScript := func(script string) error {
		if _, err := runtime.vm.RunString(script); err != nil {
			return err
		}

		downstreamFunction, ok := goja.AssertFunction(runtime.vm.Get("upstream"))
		if !ok {
			return errors.New("Unable to load downstreamFunction")
		}

		upstreamFunction, ok := goja.AssertFunction(runtime.vm.Get("downstream"))
		if !ok {
			return errors.New("Unable to load upstreamFunction")
		}

		runtime.downstreamFunction = downstreamFunction
		runtime.upstreamFunction = upstreamFunction

		return nil
	}

	if err := loadScript(script); err != nil {
		loadScript(*previousScript)
	}

	runtime.script = &script
	return nil

}

func (runtime *Runtime) ProcessDownstream(context *DownstreamContext) (*DownstreamOutput, error) {

	res, err := runtime.downstreamFunction(goja.Undefined(), runtime.vm.ToValue(context))
	if err != nil {
		return nil, err
	}

	obj := res.Export().(map[string]interface{})

	return &DownstreamOutput{
		Attributes: obj["attributes"].(map[string]interface{}),
		NameID:     obj["nameID"].(string),
	}, nil
}

func (runtime *Runtime) ProcessUpstream(input *UpstreamContext) (*UpstreamOutput, error) {

	res, err := runtime.upstreamFunction(goja.Undefined(), runtime.vm.ToValue(input))
	if err != nil {
		return nil, err
	}
	obj := res.Export().(map[string]interface{})

	output := &UpstreamOutput{}

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
