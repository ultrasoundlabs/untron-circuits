package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
)

type Block struct {
	NewBlockID  string `json:"new_block_id"`
	PrevBlockID string `json:"prev_block_id"`
	PublicKey   string `json:"public_key"`
	RawData     string `json:"raw_data"`
	Signature   string `json:"signature"`
	TxRoot      string `json:"tx_root"`
}

type DecodedBlock struct {
	NewBlockID  []byte
	PrevBlockID []byte
	PublicKey   []byte
	RawData     []byte
	Signature   []byte
	TxRoot      []byte
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

func deserializeBlocks(filename string) ([]DecodedBlock, error) {
	// Read the JSON file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Unmarshal JSON into slice of Block structs
	var blocks []Block
	err = json.Unmarshal(data, &blocks)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	// Decode hex strings into bytes
	decodedBlocks := make([]DecodedBlock, len(blocks))
	for i, block := range blocks {
		newBlockID, err := decodeHex(block.NewBlockID)
		if err != nil {
			return nil, fmt.Errorf("error decoding new_block_id: %v", err)
		}

		prevBlockID, err := decodeHex(block.PrevBlockID)
		if err != nil {
			return nil, fmt.Errorf("error decoding prev_block_id: %v", err)
		}

		publicKey, err := decodeHex(block.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("error decoding public_key: %v", err)
		}

		rawData, err := decodeHex(block.RawData)
		if err != nil {
			return nil, fmt.Errorf("error decoding raw_data: %v", err)
		}

		signature, err := decodeHex(block.Signature)
		if err != nil {
			return nil, fmt.Errorf("error decoding signature: %v", err)
		}

		txRoot, err := decodeHex(block.TxRoot)
		if err != nil {
			return nil, fmt.Errorf("error decoding tx_root: %v", err)
		}

		decodedBlocks[i] = DecodedBlock{
			NewBlockID:  newBlockID,
			PrevBlockID: prevBlockID,
			PublicKey:   publicKey,
			RawData:     rawData,
			Signature:   signature,
			TxRoot:      txRoot,
		}
	}

	return decodedBlocks, nil
}

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (c *sha2Circuit) Define(api frontend.API) error {
	h, err := sha2.New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != 32 {
		return fmt.Errorf("not 32 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

type tronBlockCircuit struct {
	NewBlockID  [32]byte
	PrevBlockID [32]byte
	PublicKey   ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	RawData     []byte
	Signature   [64]byte
	TxRoot      [32]byte
}

func (c *tronBlockCircuit) Define(api frontend.API) error {
	hash := sha256.Sum256(c.RawData)

	hashCircuit := sha2Circuit{
		In:       uints.NewU8Array(c.RawData),
		Expected: [32]uints.U8(uints.NewU8Array(hash[:])),
	}
	hashCircuit.Define(api)

	r, s, m := new(big.Int), new(big.Int), new(big.Int)
	r.SetBytes(c.Signature[:32])
	s.SetBytes(c.Signature[32:])
	m.SetBytes(hash[:])

	sig := ecdsa.Signature[emulated.Secp256k1Fr]{
		R: emulated.ValueOf[emulated.Secp256k1Fr](r),
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
	}
	msg := emulated.ValueOf[emulated.Secp256k1Fr](m)

	c.PublicKey.Verify(api, sw_emulated.GetSecp256k1Params(), &msg, &sig)
	return nil
}

func main() {
	blocks, err := deserializeBlocks("input.json")
	if err != nil {
		panic(err)
	}

	pubx, puby := new(big.Int), new(big.Int)
	pubx.SetBytes(blocks[0].PrevBlockID[:32])
	puby.SetBytes(blocks[0].PrevBlockID[32:64])

	circuit := tronBlockCircuit{
		NewBlockID:  [32]byte(blocks[0].NewBlockID),
		PrevBlockID: [32]byte(blocks[0].PrevBlockID),
		PublicKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
		},
		RawData:   blocks[0].RawData,
		Signature: [64]byte(blocks[0].Signature),
		TxRoot:    [32]byte(blocks[0].TxRoot),
	}

	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}

	// 1. One time setup
	pk, _, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}

	println("compilation + setup successful")

	// 2. Proof creation
	_, err = groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
}
