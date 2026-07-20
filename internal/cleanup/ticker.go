package cleanup

import "time"

type Ticker struct {
	C <-chan time.Time
	t *time.Ticker
}

func NewTicker(d time.Duration) *Ticker {
	t := time.NewTicker(d)
	return &Ticker{C: t.C, t: t}
}

func (t *Ticker) Stop() {
	t.t.Stop()
}
