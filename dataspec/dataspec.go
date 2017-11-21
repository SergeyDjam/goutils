package dataspec

import (
	"fmt"
	"net/url"
)

type Auth struct {
	User     string
	Password string
}

type Spec struct {
	Type       string
	Host       string
	Source     string
	Parameters map[string]string
	Auth       *Auth
}

type specError struct {
	source string
	parent error
}

func (err *specError) Error() string {
	return fmt.Sprintf("dataspec: failed to parse %s (%s)", err.source, err.parent)
}

func newError(specstr string, err error) error {
	return &specError{
		source: specstr,
		parent: err,
	}
}

func New(specstr string) (*Spec, error) {
	spec := &Spec{}

	u, err := url.Parse(specstr)
	if err != nil {
		return nil, newError(specstr, err)
	}

	if u.Host != "" {
		if u.Path == "" {
			spec.Source = u.Host
		} else {
			spec.Host = u.Host
			spec.Source = u.Path
		}
	}

	return nil, nil
}
