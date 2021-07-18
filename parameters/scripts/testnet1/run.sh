./inner_snark.sh || exit

# These are dependent on each other.
./noop_program_snark.sh || exit
./outer_snark.sh || exit

./posw_snark.sh || exit
