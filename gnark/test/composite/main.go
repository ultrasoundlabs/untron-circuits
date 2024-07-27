package main

import (
	"crypto/sha256"
	"flag"
	"math/big"

	"untron-circuits/common"

	"github.com/consensys/gnark-crypto/ecc"
	sigEcdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
)

type tronBlock struct {
	NewBlockID  [32]uints.U8
	PrevBlockID [32]uints.U8
	PublicKey   ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]
	RawData     []uints.U8 `gnark:",public"`
	Hash        [32]uints.U8
	Message     emulated.Element[emulated.Secp256k1Fr]
	Signature   ecdsa.Signature[emulated.Secp256k1Fr]
}

type tronBlocksCircuit struct {
	PublicKeyAllowList [27][64]uints.U8 `gnark:",public"`
	Blocks             []tronBlock
}

func (circuit *tronBlocksCircuit) Define(api frontend.API) error {
	// Verify that constraints are valid for each block
	for _, block := range circuit.Blocks {

		blockPublicKeyXLimbs := block.PublicKey.X.Limbs
		blockPublicKeyYLimbs := block.PublicKey.Y.Limbs

		// TODO: Try to optimize if possible
		var prodEqualPublicKey frontend.Variable = 1
		for i := 0; i < len(circuit.PublicKeyAllowList); i++ {
			possiblePublicKeyXLimbs, _ := common.ByteArrayToLimbs(api, circuit.PublicKeyAllowList[i][0:32])
			possiblePublicKeyYLimbs, _ := common.ByteArrayToLimbs(api, circuit.PublicKeyAllowList[i][32:64])

			// Check that the public list of PKs has unique elements
			for j := i + 1; j < len(circuit.PublicKeyAllowList); j++ {
				var prodListUniquePublicKey frontend.Variable = 1

				pivotPublicKey := circuit.PublicKeyAllowList[i]
				otherPublicKey := circuit.PublicKeyAllowList[j]

				for k := 0; k < len(pivotPublicKey); k++ {
					// Mul 1 iif pivotPublicKey[k] == otherPublicKey[k], else Mul 0
					prodListUniquePublicKey = api.Mul(
						prodListUniquePublicKey,
						// https://github.com/Consensys/gnark/discussions/1070
						api.IsZero(api.Sub(pivotPublicKey[k].Val, otherPublicKey[k].Val)),
					)
				}
				api.AssertIsEqual(prodListUniquePublicKey, 0)
			}

			// Check that the sent public key is in the list of PKs
			var sumEqualPublicKey frontend.Variable = 0

			// Check X Limbs
			for j := 0; j < len(blockPublicKeyXLimbs); j++ {
				// Adds 1 iif blockPublicKeyXLimbs[j] != possiblePublicKeyXLimbs[j]
				sumEqualPublicKey = api.Add(
					sumEqualPublicKey,
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

			// If for all j, each limb is equal then sumEqualPublicKey should be equal to 0
			prodEqualPublicKey = api.Mul(prodEqualPublicKey, sumEqualPublicKey)
		}

		// Assert that prodEqualPublicKey must be equal to 0 (i.e the public key is in the list)
		api.AssertIsEqual(prodEqualPublicKey, 0)

		// Create circuit that checks that sha256(circuit.RawData) == circuit.Hash
		hashCircuit := common.Sha2Circuit{
			In:       block.RawData,
			Expected: block.Hash,
		}
		hashCircuit.Define(api)

		// Note: Since sha256 output is 256 bits and secp256k1 is 256 bits, then there is no need to check for excess
		// Convert Circuit.Hash to Limbs (little endian)
		var HashLimbs, err = common.ByteArrayToLimbs(api, block.Hash[:])
		if err != nil {
			return err
		}

		// Compare to circuit.Message (compare each Limb)
		for i := 0; i < len(HashLimbs); i++ {
			api.AssertIsEqual(HashLimbs[i], block.Message.Limbs[i])
		}

		// Verify public key signature
		block.PublicKey.Verify(api, sw_emulated.GetSecp256k1Params(), &block.Message, &block.Signature)
	}

	// Check that block N-1 newBlockID == block N prevBlockID
	for i := 1; i < len(circuit.Blocks); i++ {
		for j := 0; j < 32; j++ {
			api.AssertIsEqual(circuit.Blocks[i-1].NewBlockID[j].Val, circuit.Blocks[i].PrevBlockID[j].Val)
		}
	}

	return nil
}

func main() {
	var blocksPath string
	var srsPath string

	flag.StringVar(&blocksPath, "blocks", "input.json", "Path to blocks JSON file")
	flag.StringVar(&srsPath, "srs", "srs.json", "Path to SRS JSON file")

	flag.Parse()

	blocks, err := common.DeserializeBlocks(blocksPath)
	if err != nil {
		panic(err)
	}

	srs, err := common.DeserializeSrs(srsPath)
	if err != nil {
		panic(err)
	}

	// Build circuit
	circuit := tronBlocksCircuit{
		Blocks: make([]tronBlock, len(blocks)),
	}
	for i := 0; i < len(blocks); i++ {
		// This is neccessary to avoid uninitialized slice error
		// See: https://github.com/Consensys/gnark/issues/970
		circuit.Blocks[i].RawData = make([]uints.U8, 105)
	}

	// Compile circuit
	println("Compiling circuit...")
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	println("Circuit compiled")

	pubKeyAllowList := make([][]uints.U8, len(srs))
	for i, sr := range srs {
		pubKeyAllowList[i] = uints.NewU8Array(sr.PublicKey)
	}

	var fixedSizePublicKeyAllowList [27][64]uints.U8
	for i := 0; i < len(pubKeyAllowList); i++ {
		copy(fixedSizePublicKeyAllowList[i][:], pubKeyAllowList[i])
	}

	var tronBlocks []tronBlock = make([]tronBlock, len(blocks))
	// Fill tronBlocks with block information
	for i, block := range blocks {
		pubx, puby := new(big.Int), new(big.Int)
		pubx.SetBytes(block.PublicKey[:32])
		puby.SetBytes(block.PublicKey[32:64])

		r, s := new(big.Int), new(big.Int)
		r.SetBytes(block.Signature[:32])
		s.SetBytes(block.Signature[32:64])

		input := block.RawData
		hash := sha256.Sum256(input)
		msg := sigEcdsa.HashToInt(hash[:])

		tronBlocks[i] = tronBlock{
			NewBlockID:  [32]uints.U8(uints.NewU8Array(block.NewBlockID)),
			PrevBlockID: [32]uints.U8(uints.NewU8Array(block.PrevBlockID)),
			PublicKey: ecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
			},
			RawData: uints.NewU8Array(input),
			Hash:    [32]uints.U8(uints.NewU8Array(hash[:])),
			Message: emulated.ValueOf[emulated.Secp256k1Fr](msg),
			Signature: ecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
		}
	}

	assignment := tronBlocksCircuit{
		PublicKeyAllowList: fixedSizePublicKeyAllowList,
		Blocks:             tronBlocks,
	}

	println("Assigning witness...")
	_, err = frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	println("Witness assigned")

	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
}
