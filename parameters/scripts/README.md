# Parameter Scripts

These scripts will run the parameter setup programs in the `examples` folder and move the resulting `.params`
and `.checksum` files to `testnet*` folder under the `src` directory.

If the parameter size has changed, you will need to manually update these in each corresponding struct.

To perform the program SNARK parameter generation only, run:
```$xslt
./program_snark.sh
```

To perform the inner SNARK parameter generation only, run:
```$xslt
./inner_snark.sh
```

To perform the outer SNARK parameter generation only, run:
```$xslt
./outer_snark.sh
```

To perform the PoSW SNARK parameter generation only, run:
```$xslt
./posw_snark.sh
```

To perform the genesis block generation only, run:
```$xslt
./genesis_block_setup.sh
```
