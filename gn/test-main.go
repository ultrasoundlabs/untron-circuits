package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	
	sigEcdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc"
	//"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	//"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
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

// https://github.com/Consensys/gnark/discussions/802
func byteArrayToLimbs(api frontend.API, array []uints.U8) ([]frontend.Variable, error) {
	ret := make([]frontend.Variable, (len(array)+7)/8)
	ap := make([]uints.U8, 8*len(ret)-len(array))
	for i := range ap {
		ap[i] = uints.NewU8(0)
	}
	array = append(ap, array...)
	for i := range ret {
		ret[len(ret)-1-i] = api.Add(
			api.Mul(1<<0, array[8*i+7].Val),
			api.Mul(1<<8, array[8*i+6].Val),
			api.Mul(1<<16, array[8*i+5].Val),
			api.Mul(1<<24, array[8*i+4].Val),
			api.Mul(1<<32, array[8*i+3].Val),
			api.Mul(1<<40, array[8*i+2].Val),
			api.Mul(1<<48, array[8*i+1].Val),
			api.Mul(1<<56, array[8*i+0].Val),
		)
	}
	return ret, nil
}

type sha2Circuit struct {
	In       []uints.U8
	Expected [32]uints.U8
}

func (circuit *sha2Circuit) Define(api frontend.API) error {
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

type tronBlockCircuit struct {
	//NewBlockID  [32]byte
	//PrevBlockID [32]byte
	// TODO: 	Set to 27 and import it from some file. Ideally add to witness as []uints.U8 and then convert to limbs
	// 			using byteArrayToLimbs method. Then just compare limbs
	PublicKeyAllowList	[2]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr] `gnark:",public"`
	PublicKey   		ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	RawData 			[]uints.U8 `gnark:",public"`
	Hash		 		[32]uints.U8
	Message	 			emulated.Element[emulated.Secp256k1Fr]
	Signature   		ecdsa.Signature[emulated.Secp256k1Fr]
	//TxRoot      [32]byte
}

func (circuit *tronBlockCircuit) Define(api frontend.API) error {
	// TODO: Check that the public list of PKs contains a list of different PKs

	blockPublicKeyXLimbs := circuit.PublicKey.X.Limbs
	blockPublicKeyYLimbs := circuit.PublicKey.Y.Limbs

	// TODO: See how to optimize (circuit-breakers? / continue)
	var prodEqualPublicKey frontend.Variable = 1
	for i := 0; i < len(circuit.PublicKeyAllowList); i++ {
		possiblePublicKeyXLimbs := circuit.PublicKeyAllowList[i].X.Limbs
		possiblePublicKeyYLimbs := circuit.PublicKeyAllowList[i].Y.Limbs

		var sumEqualPublicKey frontend.Variable = 0	
		// Check X Limbs
		for j := 0; j < len(blockPublicKeyXLimbs); j++ {
			// Adds 1 iif blockPublicKeyXLimbs[j] != possiblePublicKeyXLimbs[j]
			sumEqualPublicKey = api.Add(
				sumEqualPublicKey, 
				// https://github.com/Consensys/gnark/discussions/1070
				api.Sub(1, api.IsZero(api.Sub(blockPublicKeyXLimbs[j], possiblePublicKeyXLimbs[j]))),
			)
		}

		// Check Y Limbs
		for j := 0; j < len(blockPublicKeyYLimbs); j++ {
			// Adds 1 iif blockPublicKeyYLimbs[j] != possiblePublicKeyYLimbs[j]
			sumEqualPublicKey = api.Add(
				sumEqualPublicKey, 
				api.Sub(1, api.IsZero(api.Sub(blockPublicKeyYLimbs[j], possiblePublicKeyYLimbs[j]))),
			)
		}

		fmt.Println("sumEqualPublicKey: ", sumEqualPublicKey)
		fmt.Println("prodEqualPublicKey: ", prodEqualPublicKey)

		// If for all j, each limb is equal then sumEqualPublicKey should be equal to 0
		prodEqualPublicKey = api.Mul(prodEqualPublicKey, sumEqualPublicKey)
	}

	// Assert that prodEqualPublicKey must be equal to 0 (i.e the public key is in the list)
	api.AssertIsEqual(prodEqualPublicKey, 0)

	// Create circuit that checks that sha256(circuit.RawData) == circuit.Hash
	hashCircuit := sha2Circuit{
		In:       circuit.RawData,
		Expected: circuit.Hash,
	}
	hashCircuit.Define(api)

	// Note: Since sha256 output is 256 bits and sec256k1 is 256 bits, then there is no need to check for excess
	// Convert Circuit.Hash to Limbs (little endian)
	var HashLimbs, err = byteArrayToLimbs(api, circuit.Hash[:])
	if err != nil {
		return err
	}

	// Compare to circuit.Message (compare each Limb)
	for i := 0; i < len(HashLimbs); i++ {
		api.AssertIsEqual(HashLimbs[i], circuit.Message.Limbs[i])
	}	

	circuit.PublicKey.Verify(api, sw_emulated.GetSecp256k1Params(), &circuit.Message, &circuit.Signature)
	return nil
}

func main() {
	blocks, err := deserializeBlocks("input.json")
	if err != nil {
		panic(err)
	}

	for _, block := range blocks {
		pubx, puby := new(big.Int), new(big.Int)
		pubx.SetBytes(block.PublicKey[:32])
		puby.SetBytes(block.PublicKey[32:64])

		r, s := new(big.Int), new(big.Int)
		r.SetBytes(block.Signature[:32])
		s.SetBytes(block.Signature[32:64])

		input := block.RawData
		hash := sha256.Sum256(input)
		msg := sigEcdsa.HashToInt(hash[:])

		fmt.Println("Hash as hex: ", hex.EncodeToString(hash[:]))

		assignment := &tronBlockCircuit{
			//NewBlockID:  [32]byte(block.NewBlockID),
			//PrevBlockID: [32]byte(block.PrevBlockID),
			PublicKeyAllowList: [2]ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				{
					X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
					Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
				},
				{
					X: emulated.ValueOf[emulated.Secp256k1Fp](puby),
					Y: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
				},
			},
			PublicKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
			},
			RawData: uints.NewU8Array(input),
			Hash: [32]uints.U8(uints.NewU8Array(hash[:])),
			Message: emulated.ValueOf[emulated.Secp256k1Fr](msg),
			Signature: ecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			//TxRoot:    [32]byte(block.TxRoot),
		}

		fmt.Println("assignment PK: ", assignment.PublicKey)
		fmt.Println("assignment RD: ", assignment.RawData)
		fmt.Println("assignment HASH: ", assignment.Hash)
		fmt.Println("assignment MSG: ", assignment.Message)
		fmt.Println("assignment SIG: ", assignment.Signature)

		circuit := &tronBlockCircuit{
			// This is neccessary to avoid uninitialized slice error
			// See: https://github.com/Consensys/gnark/issues/970
			RawData: make([]uints.U8, 105),
		}

		err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
		if err != nil {
			panic(err)
		}
	}

	/*println("Setting up groth16...")
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
	println("Proof verified")*/
}
