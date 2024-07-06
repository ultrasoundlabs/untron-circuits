use hex_literal::hex;
use std::time::Instant;
use plonky2::{
    field::{
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field},
    },
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    },
};

use plonky2_ecdsa::{
    curve::{
        secp256k1::Secp256K1,
        curve_types::{AffinePoint, Curve},
        ecdsa::{ECDSAPublicKey, ECDSASignature}
    },
    gadgets::{
        curve::CircuitBuilderCurve,
        ecdsa::{verify_message_circuit, ECDSAPublicKeyTarget, ECDSASignatureTarget},
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
    },
    hash::{
        sha256::{CircuitBuilderHashSha2, WitnessHashSha2},
        CircuitBuilderHash,
    },
};

fn main() {
    // Set circuit config for ECC
    let config = CircuitConfig::standard_ecc_config();

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    // Create a new circuit builder using the config
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Input block header
    let header = hex!("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e");
    let mut header_bytes = Vec::new();
    for _ in 0..header.len() {
        header_bytes.push(0);
    }
    let blocks_num = header_bytes.len() / 64 + 1;

    // Add virtual targets for hash input
    let hash_input_target = builder.add_virtual_hash_input_target(blocks_num, 512);

    // Build circuit for SHA256 hash and obtain output target
    let sha256_output_target = builder.hash_sha256(&hash_input_target);

    // Set up witness using the block header as input (provides initial values for virtual targets!)
    let mut pw = PartialWitness::new();
    pw.set_sha256_input_target(&hash_input_target, &header_bytes);

    // Reduce the hash output to a field element (apply mod p where p is the order of the field)
    let msg_hash_field_target: NonNativeTarget<Secp256K1Scalar> =
        builder.reduce(&sha256_output_target);


    // Block signature
    let signature = hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d6440603182085317e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7");

    // TODO: We should add virtual targets for the signature and the public key
    //       and then set the witness values for them

    // Public key of a SR
    // TODO: Use the whole list of public keys for all possible SRs
    let pk = ECDSAPublicKey(
        AffinePoint {
            // TODO: Add x,y coordinates of the public key
            x: <Secp256K1 as Curve>::BaseField::from_canonical_u64(0x1),
            y: <Secp256K1 as Curve>::BaseField::from_canonical_u64(0x1),
            zero: false,
        }
    );

    // Create public key target 
    let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));

    // Transform hex signature to ECDSASignature
    let sig: ECDSASignature<Secp256K1> = ECDSASignature {
        // TODO: Get {r, s} from hex signature
        r: Secp256K1Scalar::from_canonical_u64(0x1),
        s: Secp256K1Scalar::from_canonical_u64(0x1),
    };

    // Create targets for r and s
    let ECDSASignature { r, s } = sig;
    let r_target = builder.constant_nonnative(r);
    let s_target = builder.constant_nonnative(s);
    let sig_target = ECDSASignatureTarget {
        r: r_target,
        s: s_target,
    };

    // Now that we have created all targets, create the verifier circuit
    verify_message_circuit(&mut builder, msg_hash_field_target, sig_target, pk_target);

    dbg!(builder.num_gates());

    let start = Instant::now();
    println!("Building circuit...");
    let data = builder.build::<C>();
    let duration = start.elapsed();
    println!("Circuit building duration: {:?}", duration);

    let start = Instant::now();
    println!("Proving...");
    let proof = data.prove(pw.clone()).unwrap();
    let duration = start.elapsed();
    println!("Proving duration: {:?}", duration);

    println!("Verifying...");
    let start = Instant::now();
    let _verified = data.verify(proof).is_ok();
    let duration = start.elapsed();
    println!("Verification duration: {:?}", duration);
}