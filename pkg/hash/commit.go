package hash

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/taurusgroup/multi-party-sig/internal/params"
)

type (
	Commitment   []byte
	Decommitment []byte
)

// WriteTo implements the io.WriterTo interface for Commitment.
func (c Commitment) WriteTo(w io.Writer) (int64, error) {
	if c == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(c)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (Commitment) Domain() string {
	return "Commitment"
}

func (c Commitment) Validate() error {
	if l := len(c); l != DigestLengthBytes {
		return fmt.Errorf("commitment: incorrect length (got %d, expected %d)", l, DigestLengthBytes)
	}
	for _, b := range c {
		if b != 0 {
			return nil
		}
	}
	return errors.New("commitment: commitment is 0")
}

// WriteTo implements the io.WriterTo interface for Decommitment.
func (d Decommitment) WriteTo(w io.Writer) (int64, error) {
	if d == nil {
		return 0, io.ErrUnexpectedEOF
	}
	n, err := w.Write(d)
	return int64(n), err
}

// Domain implements WriterToWithDomain, and separates this type within hash.Hash.
func (Decommitment) Domain() string {
	return "Decommitment"
}

func (d Decommitment) Validate() error {
	if l := len(d); l != params.SecBytes {
		return fmt.Errorf("decommitment: incorrect length (got %d, expected %d)", l, params.SecBytes)
	}
	for _, b := range d {
		if b != 0 {
			return nil
		}
	}
	return errors.New("decommitment: decommitment is 0")
}

// Commit creates a commitment to data, and returns a commitment hash, and a decommitment string such that
// commitment = h(data, decommitment).
func (hash *Hash) Commit(data ...interface{}) (Commitment, Decommitment, error) {
	var err error
	decommitment := Decommitment(make([]byte, params.SecBytes))
	if _, err = rand.Read(decommitment); err != nil {
		return nil, nil, fmt.Errorf("hash.Commit: failed to generate decommitment: %w", err)
	}

	commitment, err := hash.computeCommitment(data, decommitment)
	if err != nil {
		return nil, nil, err
	}

	return commitment, decommitment, nil
}

// Decommit verifies that the commitment corresponds to the data and decommitment such that
// commitment = h(data, decommitment).
func (hash *Hash) Decommit(c Commitment, d Decommitment, data ...interface{}) bool {
	var err error
	if err = c.Validate(); err != nil {
		return false
	}
	if err = d.Validate(); err != nil {
		return false
	}

	computedCommitment, err := hash.computeCommitment(data, d)
	if err != nil {
		return false
	}
	return bytes.Equal(computedCommitment, c)
}

func (hash *Hash) computeCommitment(data []interface{}, d Decommitment) (Commitment, error) {
	h := hash.Clone()

	for _, item := range data {
		if err := h.WriteAny(item); err != nil {
			return nil, err
		}
	}

	err := h.WriteAny(d)
	if err != nil {
		return nil, err
	}
	return h.Sum(), nil
}
