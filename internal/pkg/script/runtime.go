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

func NewRuntime(logger logger.Interface) (*Runtime, error) {

	vm := goja.New()
	vm.SetFieldNameMapper(goja.UncapFieldNameMapper())

	/*
		Global Scripts
	*/
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

		upstreamFunction, ok := goja.AssertFunction(runtime.vm.Get("upstream"))
		if !ok {
			return errors.New("unable to load downstreamFunction")
		}

		downstreamFunction, ok := goja.AssertFunction(runtime.vm.Get("downstream"))
		if !ok {
			return errors.New("unable to load upstreamFunction")
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

	return createDownstreamOutput(obj), nil
}

func (runtime *Runtime) ProcessUpstream(input *UpstreamContext) (*UpstreamOutput, error) {

	res, err := runtime.upstreamFunction(goja.Undefined(), runtime.vm.ToValue(input))
	if err != nil {
		return nil, err
	}
	obj := res.Export().(map[string]interface{})

	return createUpstreamOutput(obj), nil
}
