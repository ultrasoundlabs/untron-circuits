use hex_literal::hex;
use std::time::Instant;
use num::bigint::BigUint;
use plonky2::{
    field::{
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field},
    },
    iop::witness::{
        {PartialWitness}
    },
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
        curve::{CircuitBuilderCurve},
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
    let config = CircuitConfig::wide_ecc_config();

    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;
    const D: usize = 2;

    // Create a new circuit builder using the config
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let mut pw = PartialWitness::new();
    
    // Input block header
    let header = hex!("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e");
    let mut header_bytes = Vec::new();
    for i in 0..header.len() {
        header_bytes.push(header[i]);
    }
    let blocks_num = header_bytes.len() / 64 + 1;

    // Add virtual targets for hash input
    let hash_input_target = builder.add_virtual_hash_input_target(blocks_num, 512);

    // Build circuit for SHA256 hash and obtain output target
    let sha256_output_target = builder.hash_sha256(&hash_input_target);

    // Reduce the hash output to a field element (apply mod p where p is the order of the field)
    let msg_hash_field_target: NonNativeTarget<Secp256K1Scalar> =
        builder.reduce(&sha256_output_target);
    
    // Set up witness using the block header as input (provides initial values for virtual targets!)
    pw.set_sha256_input_target(&hash_input_target, &header_bytes);
    
    // Use when testing only ECDSA verification
    /*let msg_hash_field_target: NonNativeTarget<Secp256K1Scalar> = builder.constant_nonnative(
        Secp256K1Scalar::from_noncanonical_biguint(
            BigUint::from_bytes_be(&hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d644060318208531"))
        ),
    );*/

    // Create virtual input target for pk
    let pk_target: ECDSAPublicKeyTarget<Secp256K1> = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());

    // Create virtual input targets for r and s
    let r_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let s_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let sig_target = ECDSASignatureTarget::<Secp256K1> {
        r: r_target,
        s: s_target,
    };

    // Build verifier circuit
    verify_message_circuit(&mut builder, msg_hash_field_target.clone(), sig_target.clone(), pk_target.clone());

    // Set up witness using the public key and signature
    // TODO: Check if the public key is included in a list of public keys
    // Public key of a SR
    let public_key = hex!("12b50d6895e6010f0f7fb4e6eba00fb4eca46229649b60520bc09f8bb3b9dc26d66ab4752a2f3bd6a5e517b6a173a0a6f1cbe4867a0195d2bfeb9f823817a9e0");
    let signature = hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d6440603182085317e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7");

    let structured_public_key = ECDSAPublicKey::<Secp256K1> {
        0: AffinePoint {
            x: <Secp256K1 as Curve>::BaseField::from_noncanonical_biguint(BigUint::from_bytes_be(&public_key[0..32])),
            y: <Secp256K1 as Curve>::BaseField::from_noncanonical_biguint(BigUint::from_bytes_be(&public_key[32..64])),
            zero: false,
        }
    };
    let structured_signature = ECDSASignature::<Secp256K1> {
        r: <Secp256K1 as Curve>::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_be(&signature[0..32])),
        s: <Secp256K1 as Curve>::ScalarField::from_noncanonical_biguint(BigUint::from_bytes_be(&signature[32..64])),
    };
    
    // Set up witness using the public key and signature as targets
    pw.set_ecdsa_pk_target(&pk_target, &structured_public_key);
    pw.set_ecdsa_sig_target(&sig_target, &structured_signature);
    
    dbg!(builder.num_gates());
    dbg!(builder.num_public_inputs());

    let start = Instant::now();
    println!("Building circuit...");
    let data = builder.build::<C>();
    let duration = start.elapsed();
    println!("Circuit building duration: {:?}", duration);

    let start = Instant::now();
    println!("Proving...");
    let proof = data.prove(pw).unwrap();
    let duration = start.elapsed();
    println!("Proving duration: {:?}", duration);

    println!("Verifying...");
    let start = Instant::now();
    let _verified = data.verify(proof).is_ok();
    let duration = start.elapsed();
    println!("Verification duration: {:?}", duration);
}


use plonky2::field::types::PrimeField64;
use plonky2::iop::witness::Witness;
use plonky2_ecdsa::nonnative::biguint::WitnessBigUint;
use plonky2::field::types::PrimeField;

pub trait WitnessECDSA<F: Field + PrimeField64, C: Curve>: Witness<F> {
    fn set_ecdsa_pk_target(&mut self, target: &ECDSAPublicKeyTarget<C>, value: &ECDSAPublicKey<C>);
    fn set_ecdsa_sig_target(&mut self, target: &ECDSASignatureTarget<C>, value: &ECDSASignature<C>);
}

impl<T: Witness<F>, F: Field + PrimeField64, C: Curve> WitnessECDSA<F, C> for T {
    fn set_ecdsa_pk_target(&mut self, target: &ECDSAPublicKeyTarget<C>, pk: &ECDSAPublicKey<C>) {
        /*
        pub struct ECDSAPublicKeyTarget<C: Curve> {
            pub point: AffinePointTarget<C>,
        }
        */
        self.set_biguint_target(&target.0.x.value, &pk.0.x.to_canonical_biguint());
        self.set_biguint_target(&target.0.y.value, &pk.0.y.to_canonical_biguint());
    }

    fn set_ecdsa_sig_target(&mut self, target: &ECDSASignatureTarget<C>, sig: &ECDSASignature<C>) {
        /*
        pub struct ECDSASignatureTarget<C: Curve> {
            pub r: NonNativeTarget<C::ScalarField>,
            pub s: NonNativeTarget<C::ScalarField>,
        }
        */
        self.set_biguint_target(&target.r.value, &sig.r.to_canonical_biguint());
        self.set_biguint_target(&target.s.value, &sig.s.to_canonical_biguint());
    }
}