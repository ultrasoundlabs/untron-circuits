package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	
	sigEcdsa "github.com/consensys/gnark-crypto/ecc/bn254/ecdsa"
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
	//NewBlockID  [32]byte
	//PrevBlockID [32]byte
	PublicKey   		ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	RawData 			[]uints.U8 `gnark:",public"`
	Hash		 		[32]uints.U8
	Message	 			emulated.Element[emulated.Secp256k1Fr]
	Signature   		ecdsa.Signature[emulated.Secp256k1Fr]
	//TxRoot      [32]byte
}

func (c *tronBlockCircuit) Define(api frontend.API) error {
	// TODO: Check if c.PublicKey is in a list of fixed values
	// To check if PK is in a list of values:
	// https://github.com/Consensys/gnark/discussions/1070

	// Print all the values
	fmt.Println("PK: ", c.PublicKey)
	fmt.Println("RD: ", c.RawData)
	fmt.Println("HASH: ", c.Hash)
	fmt.Println("MSG: ", c.Message)
	fmt.Println("SIG: ", c.Signature)

	// Create circuit that checks that sha256(c.RawData) == c.Hash
	hashCircuit := sha2Circuit{
		In:       c.RawData,
		Expected: c.Hash,
	}
	hashCircuit.Define(api)

	// TODO: Check that msg == hash % N
	/* 
		// HashToInt converts a hash value to an integer. Per FIPS 186-4, Section 6.4,
		// we use the left-most bits of the hash to match the bit-length of the order of
		// the curve. This also performs Step 5 of SEC 1, Version 2.0, Section 4.1.3.
		func HashToInt(hash []byte) *big.Int {
			if len(hash) > sizeFr {
				hash = hash[:sizeFr]
			}
			ret := new(big.Int).SetBytes(hash)
			excess := ret.BitLen() - sizeFrBits
			if excess > 0 {
				// func (z *Int) Rsh(x *Int, n uint) *Int
				// Rsh sets z = x >> n and returns z.
				ret.Rsh(ret, uint(excess))
			}
			return ret
		}
	*/
	// https://pkg.go.dev/github.com/consensys/gnark/frontend#API
	//hashInt := api.FromBinary(api.ToBinary(circuit.Hash))
	//bitLength := api.FieldBitLen(hashInt)
	//excess := api.Sub(bitLength, fr.Bits)

	//shifted := hashInt
	//if excess > 0 {
	//	shifted = api.Rsh(hashInt, uint(excess))
	//}

	// Enforce the constraint: Message = shifted
	//api.AssertIsEqual(circuit.Message, shifted)


	c.PublicKey.Verify(api, sw_emulated.GetSecp256k1Params(), &c.Message, &c.Signature)
	return nil
}

func main() {
	blocks, err := deserializeBlocks("input.json")
	if err != nil {
		panic(err)
	}

	pubx, puby := new(big.Int), new(big.Int)
	pubx.SetBytes(blocks[0].PublicKey[:32])
	puby.SetBytes(blocks[0].PublicKey[32:64])

	r, s := new(big.Int), new(big.Int)
	r.SetBytes(blocks[0].Signature[:32])
	s.SetBytes(blocks[0].Signature[32:64])

	input := blocks[0].RawData
	hash := sha256.Sum256(input)
	msg := emulated.ValueOf[emulated.Secp256k1Fr](sigEcdsa.HashToInt(hash[:]))

	fmt.Println("Hash as hex: ", hex.EncodeToString(hash[:]))

	assignment := tronBlockCircuit{
		//NewBlockID:  [32]byte(blocks[0].NewBlockID),
		//PrevBlockID: [32]byte(blocks[0].PrevBlockID),
		PublicKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
		},
		RawData: uints.NewU8Array(input),
		Hash: [32]uints.U8(uints.NewU8Array(hash[:])),
		Message: msg,
		Signature: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		//TxRoot:    [32]byte(blocks[0].TxRoot),
	}

	fmt.Println("assignment PK: ", assignment.PublicKey)
	fmt.Println("assignment RD: ", assignment.RawData)
	fmt.Println("assignment HASH: ", assignment.Hash)
	fmt.Println("assignment MSG: ", assignment.Message)
	fmt.Println("assignment SIG: ", assignment.Signature)

	println("Assigning witness...")
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	println("Witness assigned")

	circuit := tronBlockCircuit{
		// This is neccessary to avoid uninitialized slice error
		// See: https://github.com/Consensys/gnark/issues/970
		RawData: make([]uints.U8, len(input)),
	}

	println("Compiling circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	println("Circuit compiled")

	println("Setting up groth16...")
	// 1. One time setup
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		panic(err)
	}
	println("Groth16 setup")


	// 2. Proof creation
	println("Creating proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	println("Proof created")

	// 3. Proof verification
	println("Verifying proof...")
	publicWitness, _ := witness.Public()
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	println("Proof verified")
}
