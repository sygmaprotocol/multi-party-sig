package sign

import (
	"fmt"

	"github.com/taurusgroup/cmp-ecdsa/pkg/party"
	"github.com/taurusgroup/cmp-ecdsa/pkg/protocol"
	"github.com/taurusgroup/cmp-ecdsa/pkg/round"
	"github.com/taurusgroup/cmp-ecdsa/pkg/types"
	"github.com/taurusgroup/cmp-ecdsa/protocols/frost/keygen"
)

const (
	// Frost Sign with Threshold.
	protocolID types.ProtocolID = "frost/sign-threshold"
	// This protocol has 3 concrete rounds.
	protocolRounds types.RoundNumber = 3
)

// StartSign initiates the protocol for producing a threshold signature, with Frost.
//
// result is the result of the key generation phase, for this participant.
//
// signers is the list of all participants generating a signature together, including
// this participant.
//
// messageHash is the hash of the message a signature should be generated for.
//
// This protocol merges Figures 2 and 3 from the Frost paper:
//   https://eprint.iacr.org/2020/852.pdf
//
//
// We merge the pre-processing and signing protocols into a single signing protocol
// which doesn't require any pre-processing.
//
// Another major difference is that there's no central "Signing Authority".
// Instead, each participant independently verifies and broadcasts items as necessary.
//
// Differences stemming from this change are commented throughout the protocol.
func StartSign(result *keygen.Result, signers []party.ID, messageHash []byte) protocol.StartFunc {
	return func() (round.Round, protocol.Info, error) {
		sortedIDs := party.NewIDSlice(signers)
		helper, err := round.NewHelper(
			protocolID,
			protocolRounds,
			result.ID,
			sortedIDs,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("sign.StartSign: %w", err)
		}
		// We delay this until *after* creating the helper, that way we know that
		// sortedIDs contains no duplicates.
		if result.Threshold+1 > sortedIDs.Len() {
			return nil, nil, fmt.Errorf("sign.StartSign: insufficient number of signers")
		}
		return &round1{
			Helper:  helper,
			M:       messageHash,
			Y:       result.PublicKey,
			YShares: result.VerificationShares,
			s_i:     result.PrivateShare,
		}, helper, nil
	}
}