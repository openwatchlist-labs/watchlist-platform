package ofaccatalog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

func Load(r io.Reader) (Catalog, error) {
	d := json.NewDecoder(r)
	d.DisallowUnknownFields()
	var c Catalog
	if err := d.Decode(&c); err != nil {
		return Catalog{}, fmt.Errorf("%w: decode: %v", ErrInvalidCatalog, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return Catalog{}, fmt.Errorf("%w: trailing content: %v", ErrInvalidCatalog, err)
	}
	if err := ValidateCatalog(c); err != nil {
		return Catalog{}, err
	}
	return c, nil
}
