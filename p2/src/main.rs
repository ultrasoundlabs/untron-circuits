use hex_literal::hex;
use std::time::Instant;
use num::bigint::BigUint;
use plonky2::{
    field::{
        secp256k1_scalar::Secp256K1Scalar,
        types::{Field},
    },
    iop::witness::{
        {PartialWitness, WitnessWrite}
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
        curve::{CircuitBuilderCurve, AffinePointTarget},
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
    for i in 0..header.len() {
        header_bytes.push(header[i]);
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

    
    // TODO: Check if the public key is included in a list of public keys
    // Public key of a SR
    let public_key = hex!("12b50d6895e6010f0f7fb4e6eba00fb4eca46229649b60520bc09f8bb3b9dc26d66ab4752a2f3bd6a5e517b6a173a0a6f1cbe4867a0195d2bfeb9f823817a9e0");
    let x = &public_key[0..32];
    let y = &public_key[32..64];

    // Create virtual input target for pk
    let pk_input_target: AffinePointTarget<Secp256K1> = builder.add_virtual_affine_point_target();

    // Block signature
    let signature = hex!("b81286a92ee17057441182938c4c74113eb7bb580c3e1ad2d6440603182085317e8d1eb51453e4b058a1b6b231b7be8214b920969df35eb2dc0988e27048edd7");

    // Get r and s from signature
    let r_input = &signature[0..32];
    let s_input = &signature[32..64];

    // Create virtual input targets for r and s
    let r_input_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
    let s_input_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();

    // Now that we have created all targets, create the verifier circuit
    verify_message_circuit(&mut builder, msg_hash_field_target, &r_input_target, &s_input_target, &pk_input_target);

    // Set up witness using the public key and signature as targets
    pw.set_affine_point_target(&pk_input_target, &public_key);
    <PartialWitness<F> as WitnessECDSA<F, Secp256K1>>::set_nonnative_target_scalar(&mut pw, &r_input_target, &r_input);
    <PartialWitness<F> as WitnessECDSA<F, Secp256K1>>::set_nonnative_target_scalar(&mut pw, &s_input_target, &s_input);
    
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

pub trait WitnessECDSA<F: PrimeField64, C: Curve>: Witness<F> {
    fn set_affine_point_target(&mut self, target: &AffinePointTarget<C>, value: &[u8]);
    fn set_nonnative_target_field(&mut self, target: &NonNativeTarget<C::BaseField>, value: &[u8]);
    fn set_nonnative_target_scalar(&mut self, target: &NonNativeTarget<C::ScalarField>, value: &[u8]);
}

impl<T: Witness<F>, F: PrimeField64, C: Curve> WitnessECDSA<F, C> for T {
    fn set_affine_point_target(&mut self, target: &AffinePointTarget<C>, value: &[u8]) {
        /*
        pub struct AffinePointTarget<C: Curve> {
            pub x: NonNativeTarget<C::BaseField>,
            pub y: NonNativeTarget<C::BaseField>,
        }
        */
        println!("------------------------------------");
        println!("Setting affine point target");
        println!("Value: {:?}", value);
        println!("X: {:?}", &value[0..32]);
        println!("Y: {:?}", &value[32..64]);
        println!("Target x: {:?}", target.x);
        println!("Target y: {:?}", target.y);
        println!("Target x length: {:?}", target.x.value.limbs.len());
        println!("Target y length: {:?}", target.y.value.limbs.len());
        println!("------------------------------------");

        <T as WitnessECDSA<F, C>>::set_nonnative_target_field(self, &target.x, &value[0..32]);
        <T as WitnessECDSA<F, C>>::set_nonnative_target_field(self, &target.y, &value[32..64]);
    }

    fn set_nonnative_target_field(&mut self, target: &NonNativeTarget<C::BaseField>, value: &[u8]) {
        /*
        pub struct NonNativeTarget<FF: Field> {
            pub value: BigUintTarget,
            pub _phantom: PhantomData<FF>,
        }
        */

        println!("------------------------------------");
        println!("Setting nonnative target field");
        println!("Value: {:?}", value);
        println!("Target: {:?}", target.value);
        println!("Value as BigUint: {:?}", BigUint::from_bytes_be(value));
        println!("------------------------------------");

        let big_uint_value = &BigUint::from_bytes_be(value);
        let mut limbs = big_uint_value.to_u32_digits();
        for (i, &limb) in limbs.iter().enumerate() {
            println!("Setting limb {} to {}", i, limb);
        }

        self.set_biguint_target(&target.value, &BigUint::from_bytes_be(value)); 
    }

    fn set_nonnative_target_scalar(&mut self, target: &NonNativeTarget<C::ScalarField>, value: &[u8]) {
        /*
        pub struct NonNativeTarget<FF: Field> {
            pub value: BigUintTarget,
            pub _phantom: PhantomData<FF>,
        }
        */

        println!("------------------------------------");
        println!("Setting nonnative target scalar");
        println!("Value: {:?}", value);
        println!("Target: {:?}", target.value);
        println!("Value as BigUint: {:?}", BigUint::from_bytes_be(value));
        println!("------------------------------------");

        let big_uint_value = &BigUint::from_bytes_be(value);
        let mut limbs = big_uint_value.to_u32_digits();
        for (i, &limb) in limbs.iter().enumerate() {
            println!("Setting limb {} to {}", i, limb);
        }

        self.set_biguint_target(&target.value, &BigUint::from_bytes_be(value)); 
    }
}