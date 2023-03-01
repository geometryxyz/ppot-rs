use std::fs::File;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{LittleEndian, ReadBytesExt};
use ark_bn254::{G1Affine, G2Affine, Fq, Fq2};
use ark_ff::fields::PrimeField;
use ark_ff::FromBytes;
use ark_ff::biginteger::BigInteger256;

#[test]
pub fn read() {
    let num_g1_points_to_read = 511;
    let num_g2_points_to_read = 256;

    let ptau_file = "8.ptau";
    let mut f = File::open(ptau_file).unwrap();

    // Read the magic string (the first 4 bytes)
    let mut magic_string_buf = [0u8; 4];
    let _ = f.read_exact(&mut magic_string_buf);
    assert_eq!(std::str::from_utf8(&magic_string_buf).unwrap(), "ptau");

    // Read the version (a 32-bit little-endian uint)
    let version = f.read_u32::<LittleEndian>().unwrap();
    assert_eq!(version, 1);

    // Read the number of sections (a 32-bit little-endian uint)
    let num_sections = f.read_u32::<LittleEndian>().unwrap();
    assert_eq!(num_sections, 11);

    // section_num => (file position, section size)
    let mut sections = BTreeMap::<usize, u64>::new();

    for _ in 0..num_sections {
        let num = f.read_u32::<LittleEndian>().unwrap();
        let size = f.read_i64::<LittleEndian>().unwrap();
        let pos = f.stream_position().unwrap();
        let _ = f.seek(SeekFrom::Current(size));
        sections.insert(num as usize, pos);
    }

    // Read the header (section 1)
    let _ = f.seek(SeekFrom::Start(sections[&1]));
    let n8 = f.read_u32::<LittleEndian>().unwrap();
    let mut q_buf = vec![0u8; n8 as usize];
    let _ = f.read_exact(&mut q_buf);
    // ensure that q_buf is not all 0s
    for b in q_buf.iter() {
        assert_ne!(*b, 0u8);
    }

    // Read q_buf as an Fq element
    let q = Fq::from_le_bytes_mod_order(&q_buf);

    // q should be 0 since it's the Fq modulus
    assert_eq!(q, Fq::from(0));

    // Read the power
    let power = f.read_u32::<LittleEndian>().unwrap();
    assert_eq!(power, 8);
    
    // Read the ceremony power
    let ceremony_power = f.read_u32::<LittleEndian>().unwrap();
    assert_eq!(ceremony_power, 28);

    let max_g2_points = 1 << power;
    let max_g1_points = max_g2_points * 2 - 1;
    assert!(num_g1_points_to_read <= max_g1_points);
    assert!(num_g2_points_to_read <= max_g2_points);

    // Read the G1 points
    // Seek to section 2
    let mut g1_points = Vec::<G1Affine>::with_capacity(num_g1_points_to_read);
    let _ = f.seek(SeekFrom::Start(sections[&2]));
    for _ in 0..num_g1_points_to_read {
        let mut x_buf = [0u8; 32];
        let mut y_buf = [0u8; 32];
        let _ = f.read_exact(&mut x_buf);
        let _ = f.read_exact(&mut y_buf);

        let x_bigint = BigInteger256::read(x_buf.as_slice()).unwrap();
        let y_bigint = BigInteger256::read(y_buf.as_slice()).unwrap();
        let x = Fq::new(x_bigint);
        let y = Fq::new(y_bigint);
        let g1 = G1Affine::new(x, y, false);
        assert!(g1.is_on_curve());
        g1_points.push(g1);
    }

    // Seek to section 3
    let _ = f.seek(SeekFrom::Start(sections[&3]));

    let mut g2_points = Vec::<G2Affine>::with_capacity(num_g2_points_to_read);
    for _ in 0..num_g2_points_to_read {
        let mut x0_buf = [0u8; 32];
        let mut x1_buf = [0u8; 32];
        let mut y0_buf = [0u8; 32];
        let mut y1_buf = [0u8; 32];
        let _ = f.read_exact(&mut x0_buf);
        let _ = f.read_exact(&mut x1_buf);
        let _ = f.read_exact(&mut y0_buf);
        let _ = f.read_exact(&mut y1_buf);
        let x0_bigint = BigInteger256::read(x0_buf.as_slice()).unwrap();
        let x1_bigint = BigInteger256::read(x1_buf.as_slice()).unwrap();
        let y0_bigint = BigInteger256::read(y0_buf.as_slice()).unwrap();
        let y1_bigint = BigInteger256::read(y1_buf.as_slice()).unwrap();
        let x0 = Fq::new(x0_bigint);
        let x1 = Fq::new(x1_bigint);
        let y0 = Fq::new(y0_bigint);
        let y1 = Fq::new(y1_bigint);
        let x = Fq2::new(x0, x1);
        let y = Fq2::new(y0, y1);
        let g2 = G2Affine::new(x, y, false);
        assert!(g2.is_on_curve());
        g2_points.push(g2);
    }
}
