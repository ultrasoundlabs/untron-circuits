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
	PublicKey   ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	RawData     []uints.U8
	Signature   ecdsa.Signature[emulated.Secp256k1Fr]
	//TxRoot      [32]byte
}

func (c *tronBlockCircuit) Define(api frontend.API) error {
	// Expected hash
	fmt.Println("RawData: ", c.RawData)
	fmt.Println("PublicKey: ", c.PublicKey)
	fmt.Println("Signature: ", c.Signature)

	//rawDataBytes := make([]byte, len(c.RawData))
	//for i, u8 := range c.RawData {
	//	rawDataBytes[i] = u8.Val.(byte)
	//}

	// Hardcode the actual value of the hash until conversion from c.RawData can be done
	rawDataBytes, err := hex.DecodeString("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e")
	if err != nil {
		return err
	}
	hash := sha256.Sum256(rawDataBytes)

	// Create circuit that checks that sha256(In) == Expected
	hashCircuit := sha2Circuit{
		In:       c.RawData,
		Expected: [32]uints.U8(uints.NewU8Array(hash[:])),
	}
	hashCircuit.Define(api)

	// Use m as a message in the field of the curve
	msg := emulated.ValueOf[emulated.Secp256k1Fr](sigEcdsa.HashToInt(hash[:]))
	// 266ced7e1b0899f39771c0a9bf1e6cdfb282c7719d44592e2f877cda60099b2a
	// Print hash as hex
	fmt.Println("hash: ", hex.EncodeToString(hash[:]))
	fmt.Println("hash to int: ", sigEcdsa.HashToInt(hash[:]))
	fmt.Println("msg: ", msg)

	// Check that msg == hash % N
	// N := ecdsa.GetCurveOrder(api, sw_emulated.GetSecp256k1Params())
	// api.AssertIsEqual(msg, emulated.ValueOf[emulated.Secp256k1Fr](m.Mod(m, N)))

	c.PublicKey.Verify(api, sw_emulated.GetSecp256k1Params(), &msg, &c.Signature)
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

	assignment := tronBlockCircuit{
		//NewBlockID:  [32]byte(blocks[0].NewBlockID),
		//PrevBlockID: [32]byte(blocks[0].PrevBlockID),
		PublicKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
		},
		RawData: uints.NewU8Array(input),
		Signature: ecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		//TxRoot:    [32]byte(blocks[0].TxRoot),
	}

	fmt.Println("assignment PK: ", assignment.PublicKey)
	fmt.Println("assignment RD: ", assignment.RawData)
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
	err = groth16.Verify(proof, vk, witness)
	if err != nil {
		panic(err)
	}
	println("Proof verified")
}
