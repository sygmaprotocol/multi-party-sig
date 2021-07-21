package zkenc

import (
	"crypto/rand"
	"math/big"

	"github.com/cronokirby/safenum"
	"github.com/taurusgroup/cmp-ecdsa/pkg/hash"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/arith"
	"github.com/taurusgroup/cmp-ecdsa/pkg/math/sample"
	"github.com/taurusgroup/cmp-ecdsa/pkg/paillier"
	"github.com/taurusgroup/cmp-ecdsa/pkg/pedersen"
)

type (
	Public struct {
		// K = Enc₀(k;ρ)
		K *paillier.Ciphertext

		Prover *paillier.PublicKey
		Aux    *pedersen.Parameters
	}
	Private struct {
		// K = k ∈ 2ˡ = Dec₀(K)
		// plaintext of K
		K *big.Int

		// Rho = ρ
		// nonce of K
		Rho *big.Int
	}
)

func (p Proof) IsValid(public Public) bool {
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidModN(public.Prover.N(), p.Z2) {
		return false
	}
	return true
}

func NewProof(hash *hash.Hash, public Public, private Private) *Proof {
	NBig := public.Prover.N()
	N := safenum.ModulusFromNat(new(safenum.Nat).SetBig(NBig, NBig.BitLen()))
	kSafe := new(safenum.Int).SetBig(private.K, private.K.BitLen())
	rhoSafe := new(safenum.Nat).SetBig(private.Rho, private.Rho.BitLen())

	alpha := sample.IntervalLEpsSecret(rand.Reader)
	r := sample.UnitModNNat(rand.Reader, N)
	mu := sample.IntervalLNSecret(rand.Reader)
	gamma := sample.IntervalLEpsNSecret(rand.Reader)

	A := public.Prover.EncWithNonce(alpha.Big(), r.Big())

	commitment := &Commitment{
		S: public.Aux.Commit(kSafe, mu),
		A: A,
		C: public.Aux.Commit(alpha, gamma),
	}

	eBig := challenge(hash, public, commitment)
	e := new(safenum.Int).SetBig(eBig, eBig.BitLen())

	z1 := new(safenum.Int).Mul(e, kSafe, -1)
	z1.Add(z1, alpha, -1)

	z2 := new(safenum.Nat).ExpI(rhoSafe, e, N)
	z2.ModMul(z2, r, N)

	z3 := new(safenum.Int).Mul(e, mu, -1)
	z3.Add(z3, gamma, -1)

	return &Proof{
		Commitment: commitment,
		Z1:         z1.Big(),
		Z2:         z2.Big(),
		Z3:         z3.Big(),
	}
}

func (p Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	prover := public.Prover

	if !arith.IsInIntervalLPrimeEps(p.Z1) {
		return false
	}

	e := challenge(hash, public, p.Commitment)

	if !public.Aux.Verify(p.Z1, p.Z3, p.C, p.S, e) {
		return false
	}

	{
		// lhs = Enc(z₁;z₂)
		lhs := prover.EncWithNonce(p.Z1, p.Z2)

		// rhs = (e ⊙ K) ⊕ A
		rhs := public.K.Clone().Mul(prover, e).Add(prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, public Public, commitment *Commitment) *big.Int {
	_, _ = hash.WriteAny(public.Aux, public.Prover, public.K,
		commitment.S, commitment.A, commitment.C)

	return sample.IntervalScalar(hash)
}
