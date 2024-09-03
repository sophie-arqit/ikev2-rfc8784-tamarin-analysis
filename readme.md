This repository contains the analysis corresponding to the article 
"Formal verification of the post-quantum security properties of IKEv2 PPK (RFC 8784) using the Tamarin Prover and CPSA", by Sophie Stevens, Paul D. Rowe and Emily Gray.

The Tamarin files (.spthy) should be run using the Tamarin prover https://tamarin-prover.github.io/.
The CPSA file (.scm) should be run using CPSA https://hackage.haskell.org/package/cpsa.

There are three Tamarin files:
  - IKEv2-PSK_main.spthy; this is the main analysis; it assumes that Create Child occurs before Rekeying
  - IKEv2-PSK_createChild_afterRekey.spthy; similar to above, except that Create Child occurs after Rekeying
  - IKEv2-main-mitigation.spthy; this analyses the recommendation that we make in the article that the PPK be automatically integrated into all keys as soon as possible.

There are three files associated to the CPSA analysis:
  - rfc8784_ss.scm; this is the main analysis including both variations of whether Rekeying occurs before or after Create Child
  - rfc8784_all_shapes.xhtml; this file has all shapes
  - rfc8784_key_integrity_shape.xhtml; this file has only the shape corresponding to the key integrity attack (shape 90 in the previous)
