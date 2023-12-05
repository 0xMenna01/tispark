use alloc::vec::Vec;
use pink_extension::chain_extension::{signing, SigType};
use scale::{Decode, Encode};

pub type ContractSigType = signing::SigType;
type Signature = Vec<u8>;

#[derive(Encode, Decode)]
#[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
pub struct ContractSignature {
    sig_type: ContractSigType,
    signature: Signature,
}

impl ContractSignature {
    pub fn signature(&self) -> Signature {
        self.signature.clone()
    }

    fn new(sig_type: ContractSigType, signature: Signature) -> Self {
        Self {
            sig_type,
            signature,
        }
    }
}

impl From<SigningData> for ContractSignature {
    fn from(value: SigningData) -> Self {
        let signature = match value.2 {
            SigType::Ed25519 => signing::sign(&value.1, &value.0, ContractSigType::Ed25519),
            SigType::Sr25519 => signing::sign(&value.1, &value.0, ContractSigType::Sr25519),
            SigType::Ecdsa => signing::sign(&value.1, &value.0, ContractSigType::Ecdsa),
        };

        ContractSignature::new(value.2, signature)
    }
}

pub type ContractSecretKey = Vec<u8>;
pub type ContractPubKey = Vec<u8>;
pub type ContractMsg = Vec<u8>;

pub struct SigningData(ContractSecretKey, ContractMsg, ContractSigType);

impl SigningData {
    pub fn new(secret: ContractSecretKey, msg: ContractMsg, msg_type: ContractSigType) -> Self {
        SigningData(secret, msg, msg_type)
    }
}
