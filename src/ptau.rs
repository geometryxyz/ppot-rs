use std::fs::File;
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use byteorder::{LittleEndian, ReadBytesExt};
use ark_bn254::{G1Affine, G2Affine, Fq, Fq2};
use ark_ff::fields::PrimeField;
use ark_ff::FromBytes;
use ark_ff::biginteger::BigInteger256;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidMagicString,
    InvalidVersion,
    InvalidPrimeOrder,
    InvalidNumSections,
    InvalidNumG1Points,
    InvalidNumG2Points,
    InvalidG1Point,
    InvalidG2Point,
}

pub fn read(
    ptau_file: &str,
    num_g1_points: usize,
    num_g2_points: usize,
) -> Result<(Vec<G1Affine>, Vec<G2Affine>), Error> {
    let mut f = File::open(ptau_file).unwrap();

    // Read the magic string (the first 4 bytes)
    let mut magic_string_buf = [0u8; 4];
    let _ = f.read_exact(&mut magic_string_buf);
    if std::str::from_utf8(&magic_string_buf).unwrap() != "ptau" {
        return Err(Error::InvalidMagicString);
    }

    // Read the version (a 32-bit little-endian uint)
    let version = f.read_u32::<LittleEndian>().unwrap();
    if version != 1 {
        return Err(Error::InvalidVersion);
    }

    // Read the number of sections (a 32-bit little-endian uint)
    let num_sections = f.read_u32::<LittleEndian>().unwrap();
    if num_sections != 11 {
        return Err(Error::InvalidNumSections);
    }

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
    let mut num_zeroes = 0;
    for b in q_buf.iter() {
        if *b == 0u8 {
            num_zeroes += 1;
        }
    }
    if num_zeroes == 32 {
        return Err(Error::InvalidPrimeOrder);
    }

    // Read q_buf as an Fq element
    let q = Fq::from_le_bytes_mod_order(&q_buf);

    // q should be 0 since it's the Fq modulus
    if q != Fq::from(0) {
        return Err(Error::InvalidPrimeOrder);
    }

    // Read the power
    let power = f.read_u32::<LittleEndian>().unwrap();
    
    // Read the ceremony power
    let _ceremony_power = f.read_u32::<LittleEndian>().unwrap();

    let max_g2_points = 1 << power;
    let max_g1_points = max_g2_points * 2 - 1;
    if num_g1_points > max_g1_points {
        return Err(Error::InvalidNumG1Points)
    }
    if num_g2_points > max_g2_points {
        return Err(Error::InvalidNumG2Points);
    }

    // Read the G1 points
    // Seek to section 2
    let mut g1_points = Vec::<G1Affine>::with_capacity(num_g1_points);
    let _ = f.seek(SeekFrom::Start(sections[&2]));
    for _ in 0..num_g1_points {
        let mut x_buf = [0u8; 32];
        let mut y_buf = [0u8; 32];
        let _ = f.read_exact(&mut x_buf);
        let _ = f.read_exact(&mut y_buf);

        let x_bigint = BigInteger256::read(x_buf.as_slice()).unwrap();
        let y_bigint = BigInteger256::read(y_buf.as_slice()).unwrap();
        let x = Fq::new(x_bigint);
        let y = Fq::new(y_bigint);
        let g1 = G1Affine::new(x, y, false);
        if !g1.is_on_curve() {
            return Err(Error::InvalidG1Point);
        }
        g1_points.push(g1);
    }

    // Seek to section 3
    let _ = f.seek(SeekFrom::Start(sections[&3]));

    let mut g2_points = Vec::<G2Affine>::with_capacity(num_g2_points);
    for _ in 0..num_g2_points {
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
        if !g2.is_on_curve() {
            return Err(Error::InvalidG2Point);
        }
        g2_points.push(g2);
    }
    Ok((g1_points, g2_points))
}

#[cfg(test)]
mod tests {
    use super::Error;
    use ark_bn254::{G1Affine, G2Affine, Fq, Fq2};
    use ark_ff::FromBytes;
    fn hex_to_fq(val: &str) -> Fq {
        assert_eq!(val.len(), 64);
        let bytes_vec = hex::decode(val).unwrap();
        let bytes_slice: &[u8] = bytes_vec.as_slice();

        Fq::read(bytes_slice).unwrap()
    }

    #[test]
    pub fn test_read() {
        let num_g1_points = 511;
        let num_g2_points = 256;

        let ptau_file = "8.ptau";

        let (g1_points, g2_points) = super::read(ptau_file, num_g1_points, num_g2_points).unwrap();
        assert_eq!(g1_points.len(), num_g1_points);
        assert_eq!(g2_points.len(), num_g2_points);

        // Check that the first 2 G1 points are correct
        let point_g1_0_x = Fq::from(1);
        let point_g1_0_y = Fq::from(2);
        let point_g1_1_x = hex_to_fq("cf51b65ad54479e394aef90d4b0ec4e4a1a16bbb6865614a4b5b8a0959fdd32d");
        let point_g1_1_y = hex_to_fq("f04eb3f6ef601be3d326c237feed3351de969ce6d634905a4304ba25350c6825");

        assert_eq!(g1_points[0], G1Affine::new(point_g1_0_x, point_g1_0_y, false));
        assert_eq!(g1_points[1], G1Affine::new(point_g1_1_x, point_g1_1_y, false));

        // Check that the first G2 point is correct
        let point_g2_0_x0 = hex_to_fq("edf692d95cbdde46ddda5ef7d422436779445c5e66006a42761e1f12efde0018");
        let point_g2_0_x1 = hex_to_fq("c212f3aeb785e49712e7a9353349aaf1255dfb31b7bf60723a480d9293938e19");
        let point_g2_0_y0 = hex_to_fq("aa7dfa6601cce64c7bd3430c69e7d1e38f40cb8d8071ab4aeb6d8cdba55ec812");
        let point_g2_0_y1 = hex_to_fq("5b9722d1dcdaac55f38eb37033314bbc95330c69ad999eec75f05f58d0890609");
        let point_g2_0 = G2Affine::new(
            Fq2::new(point_g2_0_x0, point_g2_0_x1),
            Fq2::new(point_g2_0_y0, point_g2_0_y1),
            false
        );
        assert_eq!(g2_points[0], point_g2_0);
    }

    #[test]
    pub fn test_read_too_few_g1() {
        let num_g1_points = 512;
        let num_g2_points = 256;

        let ptau_file = "8.ptau";

        let r = super::read(ptau_file, num_g1_points, num_g2_points);
        assert_eq!(r.err().unwrap(), Error::InvalidNumG1Points);
    }

    #[test]
    pub fn test_read_too_few_g2() {
        let num_g1_points = 511;
        let num_g2_points = 257;

        let ptau_file = "8.ptau";

        let r = super::read(ptau_file, num_g1_points, num_g2_points);
        assert_eq!(r.err().unwrap(), Error::InvalidNumG2Points);
    }
}
