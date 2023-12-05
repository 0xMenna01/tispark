use aleph_consensus_client::{ConsensusContractResult, ConsensusProof};
use ink::env::call::{ExecutionInput, Selector};
use utils::ContractRef;

pub fn verify_consensus(
    contract: &ContractRef,
    consensus_proof: ConsensusProof,
) -> ConsensusContractResult<()> {
    let exec = ExecutionInput::new(Selector::new(ink::selector_bytes!(
        "FinalityGadget::verify_consensus"
    )))
    .push_arg(consensus_proof);

    contract.query(exec)
}
