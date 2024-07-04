// Following the example from 
// https://github.com/succinctlabs/succinctx/blob/main/plonky2x/core/examples/field.rs

use plonky2x::frontend::vars::ByteVariable;
use plonky2x::prelude::{CircuitBuilder, DefaultParameters};

fn main() {

    type L = DefaultParameters;
    const D: usize = 2;

    let mut builder = CircuitBuilder::<L, D>::new();
    let var = builder.read();
    let hash = builder.sha256(&[var]);
    builder.write(hash);
    let circuit = builder.build();

    let mut input = circuit.input();
    input.write::<ByteVariable>(0x01);

    let (proof, output) = circuit.prove(&input);
    circuit.verify(&proof, &input, &output);

    let hash = output.read_all();
    println!("{:?}", hash.as_slice());
}