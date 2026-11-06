package ring

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func extensionOf(t testing.TB, circuit common.CircuitType) common.ExtensionCircuit {
	t.Helper()
	extension, ok := common.LookupExtension(circuit)
	if !ok {
		t.Fatalf("%s is not registered", circuit)
	}
	return extension
}

// requestOf is the inverse of assign, the request a client sends for assignment.
func requestOf[P any](t testing.TB, circuit common.CircuitType, assignment frontend.Circuit) *P {
	t.Helper()
	params := requestValue[P](t, assignment)
	reflect.ValueOf(params).Elem().FieldByName("CircuitType").SetString(string(circuit))
	return params
}

func requestValue[P any](t testing.TB, source any) *P {
	t.Helper()
	params := new(P)
	value := reflect.ValueOf(source)
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if err := errors.Join(unfill(reflect.ValueOf(params).Elem(), value, "")...); err != nil {
		t.Fatal(err)
	}
	return params
}

type unviewed interface {
	request() any
}

// interfaceOf is nil on an unexported embedded view, the struct case of unfill fills its fields.
func interfaceOf(v reflect.Value) any {
	if !v.CanInterface() {
		return nil
	}
	return v.Interface()
}

func unfill(dst, src reflect.Value, path string) []error {
	if dst.Kind() == reflect.Pointer {
		dst.Set(reflect.New(dst.Type().Elem()))
		return unfill(dst.Elem(), src, path)
	}
	if v, ok := interfaceOf(dst).(viewed); ok {
		view := reflect.New(reflect.TypeOf(v.view())).Elem()
		errs := unfill(view, src, path)
		if request, ok := view.Interface().(unviewed); ok {
			dst.Set(reflect.ValueOf(request.request()))
		} else if view.Type().ConvertibleTo(dst.Type()) {
			dst.Set(view.Convert(dst.Type()))
		} else {
			errs = append(errs, fmt.Errorf("cannot restore request at %s", path))
		}
		return errs
	}
	if src.Kind() == reflect.Interface {
		src = src.Elem()
	}
	switch {
	case dst.Type() == reflect.TypeOf(Field{}):
		dst.Set(reflect.ValueOf(Field{fieldOf(src)}))
	case dst.Kind() == reflect.Struct:
		var errs []error
		for i := range dst.NumField() {
			field := dst.Type().Field(i)
			if field.Anonymous {
				errs = append(errs, unfill(dst.Field(i), src, path)...)
				continue
			}
			if field.Name == "CircuitType" {
				continue
			}
			value := src.FieldByName(field.Name)
			if !value.IsValid() {
				errs = append(errs, fmt.Errorf("%s.%s: no circuit value", path, field.Name))
				continue
			}
			errs = append(errs, unfill(dst.Field(i), value, path+"."+field.Name)...)
		}
		return errs
	case dst.Kind() == reflect.Slice:
		dst.Set(reflect.MakeSlice(dst.Type(), src.Len(), src.Len()))
		var errs []error
		for i := range src.Len() {
			errs = append(errs, unfill(dst.Index(i), src.Index(i), fmt.Sprintf("%s[%d]", path, i))...)
		}
		return errs
	case dst.Kind() == reflect.Bool:
		dst.SetBool(fieldOf(src).Sign() != 0)
	case dst.CanUint():
		value := fieldOf(src)
		if !value.IsUint64() || dst.OverflowUint(value.Uint64()) {
			return []error{fmt.Errorf("%s: %s overflows %s", path, value, dst.Type())}
		}
		dst.SetUint(value.Uint64())
	default:
		return []error{fmt.Errorf("%s: no request value for %s", path, dst.Type())}
	}
	return nil
}

func fieldOf(src reflect.Value) *big.Int {
	var element fr.Element
	if _, err := element.SetInterface(src.Interface()); err != nil {
		panic(fmt.Sprintf("ring test: %v", err))
	}
	return element.BigInt(new(big.Int))
}

func (v quadPath) flat() []Field {
	var flat []Field
	for _, row := range v.Siblings {
		flat = append(flat, row...)
	}
	return flat
}

func (v enrollmentView) request() any {
	e := v.Entry
	return TrackingWrite{
		Member: e.Member, NullifierPk: e.NullifierPk, CtHash: e.CtHash, ListTag: e.ListTag,
		Index: v.Slot.Index, Path: v.Slot.flat(), LowRecord: v.Low, LowIndex: v.LowSlot.Index, LowPath: v.LowSlot.flat(),
	}
}

func (v privateOwnerView) request() any {
	return PrivateOwnerParams{ListSalt: v.ListSalt, Record: v.Record, Index: v.Path.Index, Path: v.Path.flat()}
}

func (v writeView) request() any {
	old, low := v.Old, v.Low
	return RecordWriteProofInput{
		Entry: v.Entry, Exists: v.Exists, OldNext: old.Next, OldLists: old.Lists, OldMintPolicy: old.MintPolicy, OldWithdrawalThreshold: old.WithdrawalThreshold, OldAssetLimits: old.AssetLimits,
		Index: v.Slot.Index, Path: v.Slot.flat(),
		LowMember: low.Member, LowNext: low.Next, LowLists: low.Lists, LowMintPolicy: low.MintPolicy, LowWithdrawalThreshold: low.WithdrawalThreshold, LowAssetLimits: low.AssetLimits,
		LowIndex: v.LowSlot.Index, LowPath: v.LowSlot.flat(),
	}
}

func mustMarshal(t testing.TB, params any) []byte {
	t.Helper()
	payload, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// decode follows the server's request path.
func decode(circuit common.CircuitType, payload []byte) (frontend.Circuit, error) {
	extension, ok := common.LookupExtension(circuit)
	if !ok {
		return nil, fmt.Errorf("%s is not registered", circuit)
	}
	request := extension.Request()
	if err := json.Unmarshal(payload, request); err != nil {
		return nil, err
	}
	return request.Assignment()
}

func decodePayload(t testing.TB, circuit common.CircuitType, payload []byte) frontend.Circuit {
	t.Helper()
	assignment, err := decode(circuit, payload)
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	return assignment
}

// solvedWitness decodes payload as the server does, the error is the compiled key's solve.
func solvedWitness(t testing.TB, circuit common.CircuitType, payload []byte) (witness.Witness, error) {
	t.Helper()
	full, err := frontend.NewWitness(decodePayload(t, circuit, payload), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	_, err = compileRing(t, circuit).Solve(full)
	return full, err
}

func decodeParams(t testing.TB, circuit common.CircuitType, params any) frontend.Circuit {
	t.Helper()
	return decodePayload(t, circuit, mustMarshal(t, params))
}

func verifyProof(ps *common.ExtensionProofSystem, proof *common.Proof, assignment frontend.Circuit) error {
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return err
	}
	return groth16.Verify(proof.Proof, ps.VerifyingKey, witness)
}
