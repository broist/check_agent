//go:build !linux

package collector

import (
	"errors"

	"github.com/broist/check_agent/internal/model"
)

type Collector struct{}

type Paths struct {
	ProcRoot      string
	SysRoot       string
	HostRoot      string
	MountInfoPath string
}

func New(_ []string) (*Collector, error) {
	return nil, errors.New("metric collection is supported only on Linux")
}

func NewWithPaths(_ []string, _ Paths) (*Collector, error) {
	return nil, errors.New("metric collection is supported only on Linux")
}

func (c *Collector) Collect() (model.Report, error) {
	return model.Report{}, errors.New("metric collection is supported only on Linux")
}
