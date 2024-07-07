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

    let headers = vec![
        hex!("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e0000000000000000000000000000000000000000000000"),
        hex!("08e8f2a19a85321220035b6c5509e2d071253199ce8a52da2bd675fcfe2b3d44b467407468d3c4681c1a200000000003bffa9cee51c47bf51c01ceab6ab3fa8f255695c2c16d15384cb3ba389df5ff1d4a1541022939a4a06cbc7b384096c1af8657ec435173af501e0000000000000000000000000000000000000000000000"),
        hex!("08b0dba19a853212207227b5fd6d56dc823f34dbf18ae081353c2c3dcb99123f12d1e93b313fdbf75d1a200000000003bffa9bdf72335d9320d629ef23b645be753e76c8a5e076592f5fb4389cf5ff1d4a15417f5e5aca5332ce5e18414d7f85bb62097cefa453501e0000000000000000000000000000000000000000000000"),    
        hex!("08f8c3a19a85321220324c00c4d1c4a5f00355db210a25308098ef68378ab2745865baa2b8930ca6011a200000000003bffa9a8255e45a249dd855f3b5fc388edb9250072431f86cfed548389bf5ff1d4a15414ce8225c8ea6c8e1e0a483132211610c765fc6df501e0000000000000000000000000000000000000000000000"),
        hex!("08c0aca19a8532122098ca48d74da8b2241a7341ce96cede30b91a50ed5fcdc1e3b5d6b6e9a1a301d71a200000000003bffa99701fa8e81c94d89e92592814b17272e2a83620b772a3610c389af5ff1d4a15411c8163d2a981b90481dcc8ca34c0f837b3305bc6501e0000000000000000000000000000000000000000000000"),
        hex!("088895a19a8532122012288a510e60645ae5a4386f6caf2450ee4ee492568d36eb83635e5385e284ea1a200000000003bffa9877a42b943f7feab73f48099ae5c071f5207a7e174ed8647d3899f5ff1d4a154178c842ee63b253f8f0d2955bbc582c661a078c9d501e0000000000000000000000000000000000000000000000"),
        hex!("08d0fda09a8532122073854e357bcfaf64abd6ecd1bb6f3a73c1d574ccad995c73f380b929994965b31a200000000003bffa97bd76a6e3c5d5688dba1d502d207ee18b60e8b859fc7048df3898f5ff1d4a1541a1a508ce5762ffd3f16bd6af93808d26d57f01eb501e0000000000000000000000000000000000000000000000"),
        hex!("0898e6a09a85321220684b608e0e0e17ab0c392a973125ee40dcd62e1e75940afe283ffe092cd0bd021a200000000003bffa96b63462fdf7ec699281373d61b826960138fa910f2a978f033897f5ff1d4a154114f2c09d3de3fe82a71960da65d4935a30b24e1f501e0000000000000000000000000000000000000000000000"),
        hex!("08e0cea09a853212207549e53b5c2119e50229c3c7f49c977b167754eaea6b185e1c3cb10ba914a8b61a200000000003bffa9522aef90e94905c9b91c18c956a5762eb3468ea7c02c83b673896f5ff1d4a154118e2e1c6cdf4b74b7c1eb84682e503213a174955501e0000000000000000000000000000000000000000000000"),
        hex!("08a8b7a09a853212203f12446edbd66d96d2517464193c88f873fc27d5e709fde39ceca8682e87e0841a200000000003bffa946b38568e53d2b11c4014a82bbe50582667f3aaaa2b8022823895f5ff1d4a1541c189fa6fc9ed7a3580c3fe291915d5c6a6259be7501e0000000000000000000000000000000000000000000000"),
        hex!("08f09fa09a853212203c2486b18dcd9da80ff6d7cb716d943239163bf82182f69796a1dc21e30cc5391a200000000003bffa931dd460d5ffa9352600541676c426f725f9636cc567364e003894f5ff1d4a1541c5614f3ebf88785fedf9d69bd82aac1353f8b431501e0000000000000000000000000000000000000000000000"),
        hex!("08b888a09a853212208e1355fffcf82750c40fda2d6d4c8e76a8e30e00034864b82e65c7fcb230aede1a200000000003bffa92de8951f75566a571ca3cbbc03af2f401db7a5bb667d0c5233893f5ff1d4a15418b0359acac03bac62cbf89c4b787cb10b3c3f513501e0000000000000000000000000000000000000000000000"),
        hex!("0880f19f9a85321220079d2b5a9af5bc88126efbe1ef35365aa9c02f4a3fb35837ab918a1bd9a1e4f01a200000000003bffa915bbfa0844a370bd210e05ab43ff70b6f1ac72834c884bdc73892f5ff1d4a1541beab998551416b02f6721129bb01b51fceceba08501e0000000000000000000000000000000000000000000000"),
        hex!("08c8d99f9a853212205f160d6f7486f1addb1cf788a6613c4743ff2d89a0f0aab20b97ef0603ac80641a200000000003bffa90400ed34da39c5568a0091a85170ec01c8acea17268ccad993891f5ff1d4a1541c81107148e5fa4b4a2edf3d5354db6c6be5b5549501e0000000000000000000000000000000000000000000000"),
        hex!("0890c29f9a85321220ff85842670e8c8fe0bacb2245d3bfc8fd8fc477de642cfec00ced07e20248c891a200000000003bffa8fd9fb5497358c11c81f481da5191dcb095a0a739967557e5d3890f5ff1d4a154167e39013be3cdd3814bed152d7439fb5b6791409501e0000000000000000000000000000000000000000000000"),
        hex!("08d8aa9f9a853212202997a04c5d725b6badac2f054ada2646630e5e93c504b10fa0210b4ac8d351e51a200000000003bffa8e7296a2a7a110d3e862d3e776e1d8e9b0603216c31de7430d388ff5ff1d4a1541d376d829440505ea13c9d1c455317d51b62e4ab6501e0000000000000000000000000000000000000000000000"),
        hex!("08a0939f9a85321220ed351757cf8d96ba69ef55c371ff1ee6105057e39b9c15bce42e3dce696b1f801a200000000003bffa8d5d0ac554bff664bbdbaaacd4e43319093c951a1923b05459388ef5ff1d4a1541a2c342b17aa0ae86abc8191498cd4633aa33a821501e0000000000000000000000000000000000000000000000"),
        hex!("08e8fb9e9a85321220899d4731a2ac4846f3daa0de9832baa01de5555351a6e5db9e49313993bbae121a200000000003bffa8c9771c0a9bf1e6cdfb282c7719d44592e2f877cda60099b2a388df5ff1d4a15418440ffd578f7a5abf3537b5f46a6980d382db581501e0000000000000000000000000000000000000000000000")
    ];
    let mut pw = PartialWitness::new();

    for header in headers {
        // Input block header
        // let header = hex!(hex!("08b0e49e9a853212206ef000a8a81ddae3419c56f9b1ba01ae1215aeffbb3865f9e8b73495c29e41e41a200000000003bffa8b92248ec47500deaedcbf8c3e20bdcaa058e5716b858ddb50388cf5ff1d4a15412a4d700c196a78f8ff7f0bf17d93fe6018396d2e501e");
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
        //let mut pw = PartialWitness::new();
        pw.set_sha256_input_target(&hash_input_target, &header_bytes);

        // Reduce the hash output to a field element (apply mod p where p is the order of the field)
        //let msg_hash_field_target: NonNativeTarget<Secp256K1Scalar> =
        //    builder.reduce(&sha256_output_target);
    }
    

    /*
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
    */
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