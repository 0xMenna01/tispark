# TISPARK: Trustless Interoperable Secure Plaintext Authenticated Revealing Key

TISPARK is a protocol that facilitates an interoperable and trustless commit-reveal scheme within the context of blockchain technology. It can be seamlessly integrated into various Substrate-based blockchains, providing a standardized solution for trustless value commitment and revelation.

This protocol offers a means to commit a value while keeping it hidden, allowing it to be revealed only when verified to exist on the blockchain. Verification is achieved through both a consensus and storage proof, ensuring the committed value's presence on the chain. Once verified, a proof is generated, and the value can be revealed.

## Use Cases
This protocol finds utility in various privacy-focused applications.

## Important NOTE:

The project is still not meant to be deployed in production. The development is still ongoing.
As a PoC, the cryptographic primitives are not yet committing, we simply used AES-GCM, howewer it requires committing schemes. 
You may follow this for a committing AEAD scheme: https://samuellucas.com/draft-lucas-generalised-committing-aead/draft-lucas-generalised-committing-aead.html
