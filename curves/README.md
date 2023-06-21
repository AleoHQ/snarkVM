
<!----------------------------------------------------------------------------->
<!-------------------- THIS MARKDOWN FILE IS AUTOGENERATED -------------------->
<!----------------------------------------------------------------------------->

# snarkvm-curves

[![Crates.io](https://img.shields.io/crates/v/snarkvm-curves.svg?color=neon)](https://crates.io/crates/snarkvm-curves)
[![Authors](https://img.shields.io/badge/authors-Aleo-orange.svg)](https://aleo.org)
[![License: GPL v3](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)

## Overview
Aleo uses a tailored set of pairing-friendly elliptic curves to perform efficient proof generation and verification.

|                     |  Edwards BLS12  |     BLS12-377      |
|:------------------- |:---------------:|:------------------:|
| Curve Type          | Twisted Edwards | Barreto-Lynn-Scott |
| Scalar Field Size   |    251 bits     |      253 bits      |
| Base Field Size     |    253 bits     |      377 bits      |
| G1 Compressed Size* |    32 bytes     |      48 bytes      |
| G2 Compressed Size* |       N/A       |      96 bytes      |

\* rounded to multiples of 8 bytes.

## Edwards BLS12
### Scalar Field

#### Modulus

##### Integer Representation
```ignore
2111115437357092606062206234695386632838870926408408195193685246394721360383
```

##### Hexadecimal Representation
```ignore
04aad957a68b2955982d1347970dec005293a3afc43c8afeb95aee9ac33fd9ff
```

##### U64 Representation (Little-Endian)
```ignore
[13356249993388743167, 5950279507993463550, 10965441865914903552, 336320092672043349]
```

#### Root of Unity

##### Integer Representation
```ignore
319259817323897909850357899558356952867916286821886696195104543796545181129
```

##### Hexadecimal Representation
```ignore
00b4b1d4c7e5e163b1af246173fdb411bdb82ac32901dcb9d289433ff2b7d5c9
```

##### U64 Representation (Little-Endian)
```ignore
[15170730761708361161, 13670723686578117817, 12803492266614043665, 50861023252832611]
```

### Base Field

#### Modulus

##### Integer Representation
```ignore
8444461749428370424248824938781546531375899335154063827935233455917409239041
```

##### Hexadecimal Representation
```ignore
12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
```

##### U64 Representation (Little-Endian)
```ignore
[725501752471715841, 6461107452199829505, 6968279316240510977, 1345280370688173398]
```

#### Root of Unity

##### Integer Representation
```ignore
5928890464389279575069867463136436689218492512582288454256978381122364252082
```

##### Hexadecimal Representation
```ignore
0d1ba211c5cc349cd7aacc7c597248269a14cda3ec99772b3c3d3ca739381fb2
```

##### U64 Representation (Little-Endian)
```ignore
[4340692304772210610, 11102725085307959083, 15540458298643990566, 944526744080888988]
```

## BLS12-377
### Scalar Field

#### Modulus

##### Integer Representation
```ignore
8444461749428370424248824938781546531375899335154063827935233455917409239041
```

##### Hexadecimal Representation
```ignore
12ab655e9a2ca55660b44d1e5c37b00159aa76fed00000010a11800000000001
```

##### U64 Representation (Little-Endian)
```ignore
[725501752471715841, 6461107452199829505, 6968279316240510977, 1345280370688173398]
```

#### Root of Unity

##### Integer Representation
```ignore
5928890464389279575069867463136436689218492512582288454256978381122364252082
```

##### Hexadecimal Representation
```ignore
0d1ba211c5cc349cd7aacc7c597248269a14cda3ec99772b3c3d3ca739381fb2
```

##### U64 Representation (Little-Endian)
```ignore
[4340692304772210610, 11102725085307959083, 15540458298643990566, 944526744080888988]
```

### Base Field

#### Modulus

##### Integer Representation
```ignore
258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177
```

##### Hexadecimal Representation
```ignore
01ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000001
```

##### U64 Representation (Little-Endian)
```ignore
[9586122913090633729, 1660523435060625408, 2230234197602682880, 1883307231910630287, 14284016967150029115, 121098312706494698]
```

#### Root of Unity

##### Integer Representation
```ignore
146552004846884389553264564610149105174701957497228680529098805315416492923550540437026734404078567406251254115855
```

##### Hexadecimal Representation
```ignore
00f3c1414ef58c54f95564f4cbc1b61fee086c1fe367c33776da78169a7f3950f1bd15c3898dd1af1c104955744e6e0f
```

##### U64 Representation (Little-Endian)
```ignore
[2022196864061697551, 17419102863309525423, 8564289679875062096, 17152078065055548215, 17966377291017729567, 68610905582439508]
```

## Contributing
 
### How to Update this README

This README is auto-generated during continuous integration.
To update this README, submit a pull request updating the appropriate Markdown file
in [documentation](./documentation) and the [configuration file](./documentation/config.json).
