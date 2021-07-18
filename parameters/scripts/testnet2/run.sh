./inner_snark.sh || exit

# These are dependent on each other.
./universal_srs.sh || exit
./noop_program_snark.sh || exit
./outer_snark.sh || exit

./posw_snark.sh || exit
