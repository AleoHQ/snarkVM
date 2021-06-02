cd /home/circleci/project/ &&
#echo "---START_LIST---"
#ls target/debug/deps
#echo "---END_LIST---"
#for file in target/debug/deps/snarkvm*-*[^\.d];
#  do
#    mkdir -p "target/cov/$(basename $file)";
#    echo "Processing target/cov/$(basename $file)"
#    /usr/local/bin/kcov --exclude-pattern=/.cargo,/usr/lib --verify "target/cov/$(basename $file)" "$file";
#  done
cargo install cargo-tarpaulin &&
cargo tarpaulin -v --workspace --manifest-path ./Cargo.toml --ciserver circle-ci --out Xml
