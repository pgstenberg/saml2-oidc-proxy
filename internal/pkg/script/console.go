package script

import (
	"github.com/crewjam/saml/logger"
	"github.com/dop251/goja"
)

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
