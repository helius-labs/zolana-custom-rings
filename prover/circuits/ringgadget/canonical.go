package ringgadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

// SplitField returns high and low of value = high*2^lowBits + low, never the split of value+q.
func SplitField(api frontend.API, rc frontend.Rangechecker, value frontend.Variable, lowBits int) (high, low frontend.Variable) {
	if lowBits < 1 || lowBits >= api.Compiler().Field().BitLen() {
		panic("split field: low width outside the field")
	}
	out, err := api.Compiler().NewHint(splitFieldHint, 2, value, lowBits)
	if err != nil {
		panic(err)
	}
	high, low = out[0], out[1]
	rc.Check(low, lowBits)
	assertCanonicalSplit(api, rc, value, high, low, lowBits)
	return high, low
}

// assertCanonicalSplit pins value = high*2^lowBits + low below q, the caller bounds low to lowBits.
func assertCanonicalSplit(api frontend.API, rc frontend.Rangechecker, value, high, low frontend.Variable, lowBits int) {
	q := api.Compiler().Field()
	// Without the bound, a high near q wraps qHigh - high into range.
	rc.Check(high, q.BitLen()-lowBits)
	api.AssertIsEqual(value, api.Add(api.Mul(high, new(big.Int).Lsh(big.NewInt(1), uint(lowBits))), low))
	qHigh := new(big.Int).Rsh(q, uint(lowBits))
	qLow := new(big.Int).Sub(q, new(big.Int).Lsh(qHigh, uint(lowBits)))
	// high is at most the high part of q.
	rc.Check(api.Sub(qHigh, high), qHigh.BitLen())
	atBound := api.IsZero(api.Sub(high, qHigh))
	// At the high part of q, low stays below the low part of q.
	rc.Check(api.Mul(atBound, api.Sub(new(big.Int).Sub(qLow, big.NewInt(1)), low)), lowBits)
}

func init() { solver.RegisterHint(splitFieldHint) }

func splitFieldHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("split field: expecting a value, a low width and two outputs")
	}
	lowBits := uint(inputs[1].Uint64())
	outputs[0].Rsh(inputs[0], lowBits)
	outputs[1].Sub(inputs[0], new(big.Int).Lsh(outputs[0], lowBits))
	return nil
}

// FieldToBytesBEWith is gadget.FieldToBytesBE through rc, both gap equations stay under 2^129 + 1 and cannot wrap modulo q.
func FieldToBytesBEWith(api frontend.API, rc frontend.Rangechecker, value frontend.Variable) [32]frontend.Variable {
	q := api.Compiler().Field()
	if q.BitLen() <= 130 || q.BitLen() > 256 {
		panic("field to bytes with: native field outside 131 to 256 bits")
	}
	w, err := api.Compiler().NewHint(fieldBytesHint, 35, value)
	if err != nil {
		panic(err)
	}
	bytes, gapLo, gapHi, carry := w[:32], w[32], w[33], w[34]
	// 1. The hint's bytes are bytes, both gap limbs fit 128 bits and the carry is a bit.
	for _, b := range bytes {
		rc.Check(b, byteBits)
	}
	rc.Check(gapLo, 128)
	rc.Check(gapHi, 128)
	api.AssertIsBoolean(carry)
	pack := func(bytes []frontend.Variable) frontend.Variable {
		n := frontend.Variable(0)
		for _, b := range bytes {
			n = api.Add(api.Mul(n, 256), b)
		}
		return n
	}
	hi, lo := pack(bytes[:16]), pack(bytes[16:])
	base := new(big.Int).Lsh(big.NewInt(1), 128)
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLo := new(big.Int).And(limit, new(big.Int).Sub(base, big.NewInt(1)))
	limitHi := new(big.Int).Rsh(limit, 128)
	// 2. The bytes plus the gap add up to q-1 without a wrap, so they encode an integer below q.
	api.AssertIsEqual(api.Add(lo, gapLo), api.Add(limitLo, api.Mul(carry, base)))
	api.AssertIsEqual(api.Add(hi, gapHi, carry), limitHi)
	// 3. The bytes recompose to value, the one encoding below q.
	api.AssertIsEqual(api.Add(api.Mul(hi, base), lo), value)
	return [32]frontend.Variable(bytes)
}

func init() { solver.RegisterHint(fieldBytesHint) }

// fieldBytesHint proposes the bytes, gap limbs and carry of a value, untrusted until FieldToBytesBEWith range-checks and recomposes them.
func fieldBytesHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 || len(outputs) != 35 {
		return errors.New("field bytes: expected one input and 35 outputs")
	}
	var bytes [32]byte
	inputs[0].FillBytes(bytes[:])
	for i, b := range bytes {
		outputs[i].SetUint64(uint64(b))
	}
	gap := new(big.Int).Sub(q, big.NewInt(1))
	gap.Sub(gap, inputs[0])
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))
	outputs[32].And(gap, mask)
	outputs[33].Rsh(gap, 128)
	outputs[34].And(inputs[0], mask)
	outputs[34].Add(outputs[34], outputs[32]).Rsh(outputs[34], 128)
	return nil
}

const gapLimbBits = 128

// AssertOrderedWhen proves lo < mid < hi over canonical field integers while a boolean enabled is set,
// the gaps lo, mid-lo-1, hi-mid-1 and q-1-hi summing to q-3 without a wrap.
func AssertOrderedWhen(api frontend.API, enabled, lo, mid, hi frontend.Variable) {
	q := api.Compiler().Field()
	if q.BitLen() <= gapLimbBits+3 || q.BitLen() > 2*gapLimbBits {
		panic("ordered when: native field outside 132..256 bits")
	}
	// 1. The caller's boolean flag either keeps the operands or swaps in the satisfiable 0 < 1 < 2.
	lo = api.Mul(enabled, lo)
	mid = api.Add(api.Mul(enabled, api.Sub(mid, 1)), 1)
	hi = api.Add(api.Mul(enabled, api.Sub(hi, 2)), 2)
	w, err := api.Compiler().NewHint(orderedGapsHint, 9, lo, mid, hi)
	if err != nil {
		panic(err)
	}
	limbs, carry := w[:8], w[8]
	// 2. Bounded limbs keep both sums below 2^131, far below q, so they hold over the integers.
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, gapLimbBits)
	}
	rc.Check(carry, 2)
	// 3. The four gaps plus 2 equal q-1 exactly, so each gap and each partial sum is below q.
	base := new(big.Int).Lsh(big.NewInt(1), gapLimbBits)
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLow := new(big.Int).And(limit, new(big.Int).Sub(base, big.NewInt(1)))
	limitHigh := new(big.Int).Rsh(limit, gapLimbBits)
	api.AssertIsEqual(api.Add(limbs[0], limbs[2], limbs[4], limbs[6], 2), api.Add(limitLow, api.Mul(base, carry)))
	api.AssertIsEqual(api.Add(limbs[1], limbs[3], limbs[5], limbs[7], carry), limitHigh)
	// 4. The gaps rebuild lo, mid and hi with a step of at least one between neighbours.
	gap := func(i int) frontend.Variable { return api.Add(limbs[2*i], api.Mul(base, limbs[2*i+1])) }
	api.AssertIsEqual(gap(0), lo)
	api.AssertIsEqual(api.Add(lo, gap(1), 1), mid)
	api.AssertIsEqual(api.Add(mid, gap(2), 1), hi)
}

func init() { solver.RegisterHint(orderedGapsHint) }

// orderedGapsHint proposes the gap limbs and the low limb carry, untrusted until
// AssertOrderedWhen range-checks and recomposes them.
func orderedGapsHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 9 {
		return errors.New("ordered gaps: expected 3 inputs and 9 outputs")
	}
	one := big.NewInt(1)
	gaps := []*big.Int{
		new(big.Int).Set(inputs[0]),
		new(big.Int).Sub(new(big.Int).Sub(inputs[1], inputs[0]), one),
		new(big.Int).Sub(new(big.Int).Sub(inputs[2], inputs[1]), one),
		new(big.Int).Sub(new(big.Int).Sub(q, one), inputs[2]),
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(one, gapLimbBits), one)
	carry := big.NewInt(2)
	for i, gap := range gaps {
		// An unordered input leaves a negative gap, zero keeps the hint total and the circuit refuses it.
		if gap.Sign() < 0 {
			gap.SetInt64(0)
		}
		outputs[2*i].And(gap, mask)
		outputs[2*i+1].Rsh(gap, gapLimbBits)
		carry.Add(carry, outputs[2*i])
	}
	outputs[8].Rsh(carry, gapLimbBits)
	return nil
}
