#[cfg(test)]
pub mod env_mocks {
    use hex::FromHex;
    use hkdf::Hkdf;
    use ink::primitives::AccountId;
    use light_client::finality::crypto::{
        verify as mock_verify, AuthorityId as MockAuthorityPublic,
        AuthoritySignature as MockSignature,
    };
    use pink_extension::chain_extension::mock as pink_mock;
    use rand::Rng;
    use schnorrkel::{
        signing_context, ExpansionMode, MiniSecretKey as MockSecretKey,
        MINI_SECRET_KEY_LENGTH as MOCK_KEY_SIZE,
    };
    use sha2::Sha256;

    use crate::types::consensus::AuthorityId;

    pub struct PhatContractEnv;

    impl PhatContractEnv {
        const SIGNING_CTX: &[u8] = b"substrate";

        fn setup_env() -> AccountId {
            // setup accounts and caller
            let accounts = ink::env::test::default_accounts::<ink::env::DefaultEnvironment>();
            ink::env::test::set_caller::<ink::env::DefaultEnvironment>(accounts.alice);

            // mock the verify pink extension function
            pink_mock::mock_verify(|_, pubkey, msg, sign| {
                let auth_public = MockAuthorityPublic::try_from(pubkey)
                    .expect("Expected to be a valid public key");
                let signature = MockSignature::try_from(sign).expect("Expected a valid signature");
                mock_verify(&auth_public, msg, &signature.into())
            });

            // mocle the sign pink extension function
            pink_mock::mock_sign(|_, key, message| {
                let keypair = MockSecretKey::from_bytes(key)
                    .expect("Expected a valid secret key")
                    .expand_to_keypair(ExpansionMode::Ed25519);
                let context = signing_context(Self::SIGNING_CTX);

                keypair.sign(context.bytes(message)).to_bytes().to_vec()
            });

            accounts.alice
        }

        pub fn setup_randomness_generation() {
            pink_mock::mock_getrandom(|length| {
                let mut rng = rand::thread_rng();
                let mut rand = vec![0u8; length as usize];
                rng.fill(&mut rand[..]);
                rand
            });
        }

        pub fn setup_with_randomness() -> AccountId {
            let caller = Self::setup_env();
            Self::setup_keys();

            caller
        }

        pub fn setup_no_randomness() -> AccountId {
            let caller = Self::setup_env();
            let (mock_secret, mock_public) = Self::mock_static_key();

            pink_mock::mock_derive_sr25519_key(move |_| mock_secret.to_vec());
            pink_mock::mock_get_public_key(move |_, _| mock_public.to_vec());

            caller
        }

        // setup a testing private and public keys used for both signing and commitments
        fn mock_static_key() -> (Vec<u8>, Vec<u8>) {
            let mock_secretkey =
                Vec::from_hex("a3e6b1571985c03a0af4c9ef51f5f8207fe4a519047a0ca51c0e73b1402ccf79")
                    .expect("The key is a valid hex!");

            let mock_pubkey =
                Vec::from_hex("0875d7a4f3162389b21aa5dc5f21497d07611c305373779746fa4b2430b47121")
                    .expect("The key is a valid hex!");

            (mock_secretkey, mock_pubkey)
        }

        fn setup_keys() {
            // mock random material
            let mut rng = rand::thread_rng();
            let raw_seed: Vec<u8> = (0..MOCK_KEY_SIZE).map(|_| rng.gen()).collect();
            // mock pink extension for the used fucntions

            pink_mock::mock_derive_sr25519_key(move |salt| {
                let hk = Hkdf::<Sha256>::from_prk(&raw_seed).expect("PRK should be large enough");
                let mut okm = [0u8; MOCK_KEY_SIZE];
                hk.expand(&salt, &mut okm)
                    .expect("32 is a valid length for Sha256 to output");

                okm.to_vec()
            });

            pink_mock::mock_get_public_key(|_, raw_secret| {
                MockSecretKey::from_bytes(raw_secret)
                    .expect("They secret is of the correct length")
                    .expand_to_public(ExpansionMode::Ed25519)
                    .to_bytes()
                    .to_vec()
            });
        }
    }

    pub struct MockAccount;

    impl MockAccount {
        pub fn mock_default() -> AccountId {
            let address =
                Vec::from_hex("d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d")
                    .unwrap();

            AccountId::try_from(address.as_ref()).unwrap()
        }

        pub fn mock_authority(hex_address: &str) -> AuthorityId {
            let address = Vec::from_hex(hex_address).expect("A valid hex is expected");
            AuthorityId::try_from(address.as_ref()).expect("A valid address is expected")
        }
    }

    pub struct MockAuthorities;

    impl MockAuthorities {
        pub fn mock_default() -> Vec<AuthorityId> {
            let authorities = vec![
                MockAccount::mock_authority(
                    "3249022c8a9b4ae72ed728147e29fc14c754a0fb7786f47a99eb7ec669a8c652",
                ),
                MockAccount::mock_authority(
                    "fdfad0e10a84e09963b47225bc3de363a1273c722a84bc5f7af34c9440b73dbe",
                ),
                MockAccount::mock_authority(
                    "ab0b60bddfc21290edfc61d42e77448bdcbfa6820217716ba96f4059a98c4d15",
                ),
                MockAccount::mock_authority(
                    "2934bd176f5d496b43e4723a0b31a94ea86669cbd290f5ac76aca05e48f4665e",
                ),
            ];
            authorities
        }
    }

    pub struct MockVecFromHex;

    impl MockVecFromHex {
        pub fn new(value: &str) -> Vec<u8> {
            Vec::from_hex(value).expect("Expected a valid hex!")
        }
    }
}
