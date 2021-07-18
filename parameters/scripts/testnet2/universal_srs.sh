# This script will run the outer SNARK setup and move the resulting `.params`
# and `.checksum` files to `params` folder under the `src` directory.
# If the parameter size has changed, you will need to manually update these in each corresponding struct.

cargo run --release --example testnet2_universal_srs || exit

mv universal_srs*.params ../../src/testnet2
mv universal_srs.checksum ../../src/testnet2