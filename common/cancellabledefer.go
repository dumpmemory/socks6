package common

type CancellableDefer struct {
	f      []func()
	cancel bool
}

func NewCancellableDefer(f func()) *CancellableDefer {
	return &CancellableDefer{
		f:      []func(){f},
		cancel: false,
	}
}

func (c *CancellableDefer) Defer() {
	if c.cancel {
		return
	}
	if c.f != nil {
		for _, v := range c.f {
			v()
		}
	}
}

func (c *CancellableDefer) Cancel() {
	c.cancel = true
}

func (c *CancellableDefer) Add(f func()) {
	c.f = append(c.f, f)
}
