package common

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type Sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (circuit *Sha2Circuit) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return err
	}

	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(circuit.In)
	res := h.Sum()

	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range circuit.Expected {
		uapi.ByteAssertEq(circuit.Expected[i], res[i])
	}
	return nil
}
