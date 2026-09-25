// SPDX-License-Identifier: AGPL-3.0-or-later
package app

import (
	"context"
	"errors"
	"time"

	"securelink2socks/internal/gateway"
	"securelink2socks/internal/securelink"
)

type State string

const (
	Starting       State = "Starting"
	Authenticating State = "Authenticating"
	Connecting     State = "Connecting"
	Ready          State = "Ready"
	Reconnecting   State = "Reconnecting"
	NeedsLogin     State = "NeedsLogin"
	Stopping       State = "Stopping"
)

type Supervisor struct {
	Backend                *gateway.Backend
	Connect                func(context.Context) (gateway.Tunnel, error)
	Notify                 func(State)
	WaitLogin              func(context.Context)
	MinBackoff, MaxBackoff time.Duration
}

func (s *Supervisor) state(v State) {
	if s.Notify != nil {
		s.Notify(v)
	}
}
func (s *Supervisor) Run(ctx context.Context) {
	defer func() { s.state(Stopping); s.Backend.Replace(nil) }()
	minimum, maximum := s.MinBackoff, s.MaxBackoff
	if minimum <= 0 {
		minimum = time.Second
	}
	if maximum < minimum {
		maximum = 30 * time.Second
	}
	delay := minimum
	s.state(Starting)
	for ctx.Err() == nil {
		s.state(Authenticating)
		t, err := s.Connect(ctx)
		if ctx.Err() != nil {
			if t != nil {
				t.Close()
			}
			return
		}
		if err == nil {
			started := time.Now()
			s.Backend.Replace(t)
			s.state(Ready)
			select {
			case <-ctx.Done():
				return
			case <-t.Done():
			}
			err = t.Err()
			s.Backend.Replace(nil)
			if time.Since(started) > time.Minute {
				delay = minimum
			}
		}
		if errors.Is(err, securelink.ErrNeedsLogin) {
			s.state(NeedsLogin)
			if s.WaitLogin != nil {
				s.WaitLogin(ctx)
			} else {
				<-ctx.Done()
			}
			delay = minimum
			continue
		}
		s.state(Reconnecting)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		delay = min(delay*2, maximum)
	}
}
