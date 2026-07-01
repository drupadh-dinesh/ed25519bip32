package hdwallet

import (
	"fmt"
	"strconv"
	"strings"
)

// DerivePath derives a path such as m/44'/0'/0/1.
func (k *ExtendedKey) DerivePath(path string) (*ExtendedKey, error) {
	if k == nil {
		return nil, ErrNilKey
	}
	if path != strings.TrimSpace(path) || path == "" {
		return nil, fmt.Errorf("%w: path must be non-empty and trimmed", ErrInvalidPath)
	}
	parts := strings.Split(path, "/")
	if parts[0] != "m" {
		return nil, fmt.Errorf("%w: path must start with m", ErrInvalidPath)
	}
	if len(parts) == 1 {
		return k.copy(), nil
	}

	current := k
	for _, component := range parts[1:] {
		if component == "" {
			return nil, fmt.Errorf("%w: empty path component", ErrInvalidPath)
		}
		hardened := strings.HasSuffix(component, "'")
		raw := strings.TrimSuffix(component, "'")
		if raw == "" || strings.HasPrefix(raw, "+") || strings.HasPrefix(raw, "-") {
			return nil, fmt.Errorf("%w: invalid component %q", ErrInvalidPath, component)
		}
		value, err := strconv.ParseUint(raw, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid component %q", ErrInvalidPath, component)
		}
		index := uint32(value)
		if hardened {
			index = Hardened(index)
		}
		current, err = current.Derive(index)
		if err != nil {
			return nil, err
		}
	}
	return current, nil
}

func (k *ExtendedKey) copy() *ExtendedKey {
	if k == nil {
		return nil
	}
	return &ExtendedKey{
		key:       cloneBytes(k.key),
		chainCode: k.chainCode,
		depth:     k.depth,
		childNum:  k.childNum,
		parentFP:  k.parentFP,
		isPrivate: k.isPrivate,
	}
}
