// Following the example from 
// https://github.com/succinctlabs/succinctx/blob/main/plonky2x/core/examples/field.rs

use bit_vec::BitVec;
use hex_literal::hex;
use plonky2x::prelude::{ByteVariable, CircuitBuilder, DefaultParameters};

fn main() {
    panic!("use tests");
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_sha256() {
        let header = hex!("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e");

        type L = DefaultParameters;
        const D: usize = 2;
        let mut builder = CircuitBuilder::<L, D>::new();

        let mut header_bytes = Vec::new();
        for _ in 0..header.len() {
            header_bytes.push(builder.read());
        }
        let hash = builder.sha256(&header_bytes);
        builder.write(hash);

        let circuit = builder.build();

        let mut input = circuit.input();
        for byte in header.iter() {
            input.write::<ByteVariable>(*byte);
        }

        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        let output = output.read_all();
        let mut hash = BitVec::with_capacity(256);
        output.iter().for_each(|f| hash.push(f.0 != 0));
        let hash = hash.to_bytes();

        assert_eq!(&hash, &hex!("266ced7e1b0899f39771c0a9bf1e6cdfb282c7719d44592e2f877cda60099b2a"));
    }

    #[test]
    fn test_secp256k1_verify() {

        // let hash = hex!("266ced7e1b0899f39771c0a9bf1e6cdfb282c7719d44592e2f877cda60099b2a");
        // let public_key_x = hex!("12b50d6895e6010f0f7fb4e6eba00fb4eca46229649b60520bc09f8bb3b9dc26");
        // let public_key_y = hex!("d66ab4752a2f3bd6a5e517b6a173a0a6f1cbe4867a0195d2bfeb9f823817a9e0");
        // let signature_r = hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d644060318208531");
        // let signature_s = hex!("7e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7");
        // let signature_v = hex!("01");

    }
}