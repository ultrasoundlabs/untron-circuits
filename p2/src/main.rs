// Following the example from 
// https://github.com/succinctlabs/succinctx/blob/main/plonky2x/core/examples/field.rs

use hex_literal::hex;
use plonky2x::prelude::{ByteVariable, CircuitBuilder, DefaultParameters};

fn main() {
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

    let hash = output.read_all();
    println!("{:?}", hash.as_slice());
}