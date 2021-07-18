# This script will run the Noop program SNARK setup and move the resulting `.params`
# and `.checksum` files to `params` folder under the `src` directory.
# If the parameter size has changed, you will need to manually update these in each corresponding struct.

cargo run --release --example testnet2_noop_program_snark || exit

mv noop_program_snark_pk.params ../../src/testnet2
mv noop_program_snark_pk.checksum ../../src/testnet2

mv noop_program_snark_vk.params ../../src/testnet2
mv noop_program_snark_vk.checksum ../../src/testnet2
