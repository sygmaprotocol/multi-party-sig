package ot

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/taurusgroup/multi-party-sig/internal/params"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

func runExtendedOT(hash *hash.Hash, choices []byte, sendSetup *CorreOTSendSetup, receiveSetup *CorreOTReceiveSetup) (*ExtendedOTSendResult, *ExtendedOTReceiveResult, error) {
	msg, receiveResult := ExtendedOTReceive(hash.Clone(), receiveSetup, choices)
	sendResult, err := ExtendedOTSend(hash.Clone(), sendSetup, 8*len(choices), msg)
	if err != nil {
		return nil, nil, err
	}
	return sendResult, receiveResult, nil
}

func TestExtendedOT(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	sendSetup, receiveSetup, err := runCorreOTSetup(pl, hash.New())
	if err != nil {
		t.Error(err)
	}
	H := hash.New()
	for i := 0; i < 1; i++ {
		_ = H.WriteAny([]byte{byte(i)})
		choices := make([]byte, 11)
		_, _ = rand.Read(choices)
		sendResult, receiveResult, err := runExtendedOT(H, choices, sendSetup, receiveSetup)
		if err != nil {
			t.Error(err)
		}
		for i := 0; i < len(choices); i++ {
			for j := 0; j < 8; j++ {
				choice := ((choices[i] >> j) & 1) == 1
				expected := make([]byte, params.SecBytes)
				if choice {
					copy(expected, sendResult._V1[(i<<3)|j][:])
				} else {
					copy(expected, sendResult._V0[(i<<3)|j][:])
				}
				if !bytes.Equal(receiveResult._VChoices[(i<<3)|j][:], expected) {
					t.Error("incorrect Extended OT")
				}
			}

		}
	}
}

func BenchmarkExtendedOT(b *testing.B) {
	b.StopTimer()
	pl := pool.NewPool(0)
	defer pl.TearDown()
	sendSetup, receiveSetup, _ := runCorreOTSetup(pl, hash.New())
	choices := make([]byte, params.SecBytes)
	_, _ = rand.Read(choices)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		runExtendedOT(hash.New(), choices, sendSetup, receiveSetup)
	}
}
