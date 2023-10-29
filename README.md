# TISPARK: Trustless Interoperable Secure Plaintext Authenticated Revealing Key

TISPARK is a protocol that facilitates an interoperable and trustless commit-reveal scheme within the context of blockchain technology. It can be seamlessly integrated into various Substrate-based blockchains, providing a standardized solution for trustless value commitment and revelation.

This protocol offers a means to commit a value while keeping it hidden, allowing it to be revealed only when verified to exist on the blockchain. Verification is achieved through a consensus proof, ensuring the committed value's presence on the chain. Once verified, a proof is generated, and the value can be revealed.

## Use Cases
This protocol finds utility in various privacy-focused applications and the realm of online gambling.

Please note that for execution, TISPARK may require the utilization of confidential smart contracts. For example, you can leverage smart contract solutions like [PhatContracts](https://phala.network/phat-contract) to integrate TISPARK into your blockchain environment seamlessly.

## Project Components
This repository hosts a Rust implementation and is organized into several crates, each serving a specific purpose:

### 1. Light Client
The "light client" crate offers a basic implementation of a stateless light client, providing the essential tools for validating state proofs. Additionally, it includes an implementation of the AlephBFT consensus client. The Aleph finality gadget is hosted at [Cardinal-Cryptography/aleph-node](https://github.com/Cardinal-Cryptography/aleph-node/tree/main/finality-aleph). The light client is designed to be extensible, allowing for the integration of other consensus proofs as needed.

### 2. Primitives
The "primitives" crate contains the core logic for the commit-reveal scheme, as well as various primitives for state verification. This is where the protocol's fundamental components and functions reside.

### 3. Crypto
The "crypto" crate is a cryptographic module that offers AES-GCM primitives. These cryptographic tools are essential for securing the protocol and its communications.

By structuring the project in this way, TISPARK provides a clear separation of concerns, making it easier to understand and extend each of its components.
