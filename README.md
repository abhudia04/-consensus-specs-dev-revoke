# consensus-specs-dev-revoke
This repo contains the update for the implementation of the pubkey-change. The consensus-spec/dev branch was cloned on 16.02.2023

# Executable Python Specs (PySpec)
The executable Python spec is built from the consensus specications, complemented with the necessary helper functions for hashing, BLS, and more. 

With this executable spec, test-generators can easily create test-vectors for client implementations, and the spec itself can be verified to be consistent and coherent through sanity tests implemented with pytest. 

This version includes a new feature - pubkey-change, which would allow validator/s to revoke their existing compromised siging key (pub-key) and replace it with a new one.

To test the revoke specs, run the test; test_process_pubkey_change.py::run_pubkey_change_processing as follows:

Run "make pyspec" before "make test"

First, make clean so remove old dependencies/broken packages:
```shell
make clean
```
Re-install the developer dependencies:
```shell
make install_test
```
Skip-if the md source file is uptodate then run:
```shell
make pyspec
make test
```

Example:
```shell
pytest --disable-bls eth2spec/test/revoke/sanity/test_blocks.py::test_successful_bls_change -s --fork=revoke
```

Note: run from tests/core/pyspec dir
Run the new test case (test_process_pubkey_change.py) against the revoke specs - mainnet.py
```shell
pytest --disable-bls eth2spec/test/revoke/block_processing/test_process_pubkey_change.py --preset=mainnet -s --fork=revoke
```

The command will enable the virtual python environment and compile all the specs
```shell
python3 -m vent vent; . venv/bin/activate; python3 setup.py pyspecdev
```

Other Notes:
pytest --disable-bls eth2spec/test/capella/sanity/test_blocks.py::test_success_exit_and_bls_change -s --fork=capella

pytest --disable-bls eth2spec/test/capella/sanity/test_blocks.py --preset=mainnet

eth2spec/test/capella/sanity/test_blocks.py::test_success_exit_and_bls_change
