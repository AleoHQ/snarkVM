# This script will run the outer SNARK setup and move the resulting `.params`
# and `.checksum` files to `params` folder under the `src` directory.
# If the parameter size has changed, you will need to manually update these in each corresponding struct.

cargo run --release --example outer_snark || exit

mv outer_snark_pk*.params ../../src/testnet1
mv outer_snark_pk.checksum ../../src/testnet1

mv outer_snark_vk.params ../../src/testnet1
mv outer_snark_vk.checksum ../../src/testnet1
