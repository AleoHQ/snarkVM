// Copyright (C) 2019-2021 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

#[cfg(test)]
mod bls12_377 {
    use crate::hash_to_curve::{hash_to_curve, try_hash_to_curve};
    use snarkvm_curves::{
        bls12_377::{G1Affine, G2Affine},
        AffineCurve,
    };
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::{BigInteger384, ConstantSerializedSize};

    #[test]
    fn hash_bls12_377_g1() {
        let g1 = try_hash_to_curve::<G1Affine>("Aleo BLS12-377 G1 in 0").unwrap();
        assert!(g1.is_on_curve());
        assert!(g1.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(G1Affine::SERIALIZED_SIZE, 384 / 8);
        assert_eq!(
            hash_to_curve::<G1Affine>("Aleo BLS12-377 G1"),
            (g1, "Aleo BLS12-377 G1 in 0".to_string(), 0)
        );

        // String representation
        assert_eq!(
            g1.x.to_string(),
            "89363714989903307245735717098563574705733591463163614225748337416674727625843187853442697973404985688481508350822",
        );
        assert_eq!(
            g1.y.to_string(),
            "3702177272937190650578065972808860481433820514072818216637796320125658674906330993856598323293086021583822603349",
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g1.x.to_repr(),
            BigInteger384::new([
                1089863619676461926,
                2031922408020517912,
                7605803015099675459,
                5499508099818543095,
                11627353473000952893,
                41837199143568307
            ])
        );
        assert_eq!(
            g1.y.to_repr(),
            BigInteger384::new([
                8946822147630122069,
                11486725844942458959,
                17739430126876114892,
                5672784675232650440,
                942928816728936680,
                1733239579958889
            ])
        );

        // Raw BigInteger representation
        assert_eq!(
            g1.x.to_repr_unchecked(),
            BigInteger384::new([
                1171681672315280277,
                6528257384425852712,
                7514971432460253787,
                2032708395764262463,
                12876543207309632302,
                107509843840671767
            ])
        );
        assert_eq!(
            g1.y.to_repr_unchecked(),
            BigInteger384::new([
                13572190014569192121,
                15344828677741220784,
                17067903700058808083,
                10342263224753415805,
                1083990386877464092,
                21335464879237822
            ])
        );
    }

    #[test]
    fn hash_bls12_377_g2() {
        let g2 = try_hash_to_curve::<G2Affine>("Aleo BLS12-377 G2 in 6").unwrap();
        assert!(g2.is_on_curve());
        assert!(g2.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(G2Affine::SERIALIZED_SIZE, 2 * 384 / 8);
        assert_eq!(
            hash_to_curve::<G2Affine>("Aleo BLS12-377 G2"),
            (g2, "Aleo BLS12-377 G2 in 6".to_string(), 6),
        );

        // String representation
        assert_eq!(
            g2.x.to_string(),
            "Fp2(170590608266080109581922461902299092015242589883741236963254737235977648828052995125541529645051927918098146183295 + 83407003718128594709087171351153471074446327721872642659202721143408712182996929763094113874399921859453255070254 * u)",
        );
        assert_eq!(
            g2.y.to_string(),
            "Fp2(1843833842842620867708835993770650838640642469700861403869757682057607397502738488921663703124647238454792872005 + 33145532013610981697337930729788870077912093258611421158732879580766461459275194744385880708057348608045241477209 * u)",
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g2.x.c0.to_repr(),
            BigInteger384::new([
                6285382596397680767,
                15748827462709656851,
                12106939604663586443,
                15333984969116343459,
                5478119782678835813,
                79865001705186672
            ])
        );
        assert_eq!(
            g2.x.c1.to_repr(),
            BigInteger384::new([
                16087313950742852142,
                593255854261604337,
                1941199260866950545,
                10849744434273544618,
                2633370935305329371,
                39048459712288691
            ])
        );
        assert_eq!(
            g2.y.c0.to_repr(),
            BigInteger384::new([
                7702421029866889285,
                16004466681641276576,
                106615717155384672,
                763522394023763305,
                16530696304726864408,
                863223330401754
            ])
        );
        assert_eq!(
            g2.y.c1.to_repr(),
            BigInteger384::new([
                14642269910726223961,
                418400088670236579,
                13367772290999385514,
                12034951455731096578,
                1807164704891090155,
                15517665349181582
            ])
        );

        // Raw BigInteger representation
        assert_eq!(
            g2.x.c0.to_repr_unchecked(),
            BigInteger384::new([
                1394603105513884269,
                11069732150289508451,
                4261960060090787184,
                13457254148541472797,
                3177258746859163322,
                82258727112085846
            ])
        );
        assert_eq!(
            g2.x.c1.to_repr_unchecked(),
            BigInteger384::new([
                12672065269715576738,
                3451530808602826578,
                9486610028138952262,
                5031487885431614078,
                9858745210421513581,
                63301617551232910
            ])
        );
        assert_eq!(
            g2.y.c0.to_repr_unchecked(),
            BigInteger384::new([
                1855632670224768760,
                2989378521406112342,
                9748867374972564648,
                3204895972998458874,
                16520689795595505429,
                61918742406142643
            ])
        );
        assert_eq!(
            g2.y.c1.to_repr_unchecked(),
            BigInteger384::new([
                1532128906028652860,
                14539073382194201855,
                10828918286556702479,
                14664598863867299115,
                483199896405477997,
                73741830940675480
            ])
        );
    }
}

#[cfg(test)]
mod bw6_761 {
    use crate::hash_to_curve::{hash_to_curve, try_hash_to_curve};
    use snarkvm_curves::{
        bw6_761::{G1Affine, G2Affine},
        AffineCurve,
    };
    use snarkvm_fields::PrimeField;
    use snarkvm_utilities::{BigInteger768, ConstantSerializedSize};

    #[test]
    fn hash_bw6_761_g1() {
        let g1 = try_hash_to_curve::<G1Affine>("Aleo BW6-761 G1 in 2").unwrap();
        assert!(g1.is_on_curve());
        assert!(g1.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(G1Affine::SERIALIZED_SIZE, 768 / 8);
        assert_eq!(
            hash_to_curve::<G1Affine>("Aleo BW6-761 G1"),
            (g1, "Aleo BW6-761 G1 in 2".to_string(), 2),
        );

        // String representation
        assert_eq!(
            g1.x.to_string(),
            "3475636518786498766590810745250126945968740010631847578009395853050342820108308881971249946821118240925527322852779996711186385119856316194209542863985484661252056926060250383124450299173357715156750061459909058938784631925098185",
        );
        assert_eq!(
            g1.y.to_string(),
            "6386045741560615474115286751221519546327665724453260780636948036691066354033553926136039329128245771826622081935656169693501570527441758504134165160161290809285880130747815459138453114895109629685668115497335848801906309831854449",
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g1.x.to_repr(),
            BigInteger768::new([
                14304550705623844553,
                16255781936664877478,
                11143826543346578983,
                12724683775331720719,
                3233330036861183058,
                168158820513473412,
                13985444146662639519,
                8702285073957815495,
                12842136209114123635,
                16740714294112745383,
                2458346450078091680,
                41296895458578010
            ]),
        );
        assert_eq!(
            g1.y.to_repr(),
            BigInteger768::new([
                5981742471712606577,
                17840704265155908863,
                18136657241925898101,
                8858161383593187557,
                5239054685806902780,
                10053010638619114654,
                9373640395283197380,
                11812058207955075752,
                14757381380144855974,
                16612200115255816278,
                14947382185210215897,
                75877860632850036
            ]),
        );

        // Raw BigInteger representation
        assert_eq!(
            g1.x.to_repr_unchecked(),
            BigInteger768::new([
                12877523079922362788,
                7752575235482070428,
                10011652029515665100,
                15977973268104179781,
                6650682096433390709,
                7089159491550934343,
                12402656740034927996,
                16078622859415237779,
                6176729449605897675,
                13861293628711269015,
                10247809388267527780,
                10528928568506906
            ]),
        );
        assert_eq!(
            g1.y.to_repr_unchecked(),
            BigInteger768::new([
                2946353734925236977,
                16176025292777111085,
                5461526384304579835,
                9030519021371797121,
                392712970462636053,
                16933452782188291054,
                15151082028748062197,
                11724317612978406850,
                9469657462524899792,
                403488069705763791,
                14811030666200823776,
                39400888622938101
            ]),
        );
    }

    #[test]
    fn hash_bw6_761_g2() {
        let g2 = try_hash_to_curve::<G2Affine>("Aleo BW6-761 G2 in 14").unwrap();
        assert!(g2.is_on_curve());
        assert!(g2.is_in_correct_subgroup_assuming_on_curve());
        assert_eq!(G2Affine::SERIALIZED_SIZE, 768 / 8);
        assert_eq!(
            hash_to_curve::<G2Affine>("Aleo BW6-761 G2"),
            (g2, "Aleo BW6-761 G2 in 14".to_string(), 14),
        );

        // String representation
        assert_eq!(
            g2.x.to_string(),
            "927956984471615468124472746554543101337527312348662621347440770917496233677004806656401789322295154757803076219469766862850983203848259151794917476784348647741097824043386936111698873760942854285698387656381822040687217598671475",
        );
        assert_eq!(
            g2.y.to_string(),
            "608205995591379252593575348853717734690994487823225986322386812170777664697317078928599401333750023327415326429631777048153067399834460761103119533693592159593385004303526978878263449123862579622710147286865775614857922338717660",
        );

        // Montgomery BigInteger representation
        assert_eq!(
            g2.x.to_repr(),
            BigInteger768::new([
                14078326491789535859,
                5990846202416124632,
                3026134793488503814,
                653008211701921174,
                17915990316536682995,
                16058387027508106514,
                14674735702293962554,
                3630233708908384537,
                11580890080272712264,
                2923549534254273490,
                12983371625827501273,
                11025819981647979
            ]),
        );
        assert_eq!(
            g2.y.to_repr(),
            BigInteger768::new([
                8990165721009979356,
                1936295271115284575,
                6893226422571030641,
                6967748571312212104,
                110103734224332952,
                6550308155478450178,
                6166710342325313409,
                12203851812441284277,
                9176183732009742483,
                14144190799670363289,
                1583259847183723747,
                7226595554930764
            ]),
        );

        // Raw BigInteger representation
        assert_eq!(
            g2.x.to_repr_unchecked(),
            BigInteger768::new([
                10634505283823758248,
                12474260491383229975,
                15569041147122342465,
                229589451343854593,
                17809542510990719370,
                7141848535003467854,
                12291544884903833552,
                10318678898116314991,
                10135148888583310199,
                7938758716343420664,
                12876992257746654479,
                28134550160207396
            ]),
        );
        assert_eq!(
            g2.y.to_repr_unchecked(),
            BigInteger768::new([
                13646097242432658323,
                4850665909724646326,
                7360412517677089449,
                12865608907432106429,
                4102018624610352121,
                17837689763279414164,
                1465321240991937963,
                14363746691071914467,
                9255969020966565367,
                8837836703783055843,
                8516967617461466404,
                41650228197102562
            ]),
        );
    }
}
