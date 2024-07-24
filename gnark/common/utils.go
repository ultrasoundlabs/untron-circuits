package common

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Block struct {
	NewBlockID  string `json:"new_block_id"`
	PrevBlockID string `json:"prev_block_id"`
	PublicKey   string `json:"public_key"`
	RawData     string `json:"raw_data"`
	Signature   string `json:"signature"`
	TxRoot      string `json:"tx_root"`
}

type SR struct {
	PublicKey string `json:"public_key"`
}

type DecodedSR struct {
	PublicKey []byte
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

func DeserializeSrs(filename string) ([]DecodedSR, error) {
	// Read the JSON file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}

	// Unmarshal JSON into slice of SR structs
	var srs []SR
	err = json.Unmarshal(data, &srs)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	// Decode hex strings into decoded SRs
	decodedSrs := make([]DecodedSR, len(srs))
	for i, sr := range srs {
		publicKey, err := decodeHex(sr.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("error decoding public_key: %v", err)
		}

		decodedSrs[i] = DecodedSR{
			PublicKey: publicKey,
		}
	}

	return decodedSrs, nil
}

func DeserializeBlocks(filename string) ([]DecodedBlock, error) {
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
func ByteArrayToLimbs(api frontend.API, array []uints.U8) ([]frontend.Variable, error) {
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
