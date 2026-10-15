//! Checksums of multipart objects: COMPOSITE checksums (a checksum of the parts' checksums,
//! `<base64>-<parts>`) and FULL_OBJECT checksums (the CRC of the whole object, combined from
//! the parts' CRCs without reading the data again).

use crate::store::meta::ChecksumAlgo;
use crate::util::{base64, unbase64};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Composite,
    FullObject,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Composite => "COMPOSITE",
            Kind::FullObject => "FULL_OBJECT",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        match s.trim().to_ascii_uppercase().as_str() {
            "COMPOSITE" => Some(Kind::Composite),
            "FULL_OBJECT" => Some(Kind::FullObject),
            _ => None,
        }
    }

    /// The kind of a stored checksum value: composite ones end in `-<parts>`.
    pub fn of(value: &str) -> Kind {
        if value.contains('-') { Kind::Composite } else { Kind::FullObject }
    }

    /// S3's rules: SHA checksums can only be composite, CRC64NVME only full-object; CRC32 and
    /// CRC32C can be either (composite by default).
    pub fn for_algo(algo: ChecksumAlgo, requested: Option<Kind>) -> Option<Kind> {
        match (algo, requested) {
            (ChecksumAlgo::Sha1 | ChecksumAlgo::Sha256, None | Some(Kind::Composite)) => Some(Kind::Composite),
            (ChecksumAlgo::Crc64Nvme, None | Some(Kind::FullObject)) => Some(Kind::FullObject),
            (ChecksumAlgo::Crc32 | ChecksumAlgo::Crc32c, None) => Some(Kind::Composite),
            (ChecksumAlgo::Crc32 | ChecksumAlgo::Crc32c, Some(k)) => Some(k),
            _ => None,
        }
    }
}

/// `x` times `vec` in GF(2), where `mat` holds the images of the unit vectors.
fn gf2_times(mat: &[u64], mut vec: u64) -> u64 {
    let mut sum = 0;
    let mut i = 0;
    while vec != 0 {
        if vec & 1 == 1 {
            sum ^= mat[i];
        }
        vec >>= 1;
        i += 1;
    }
    sum
}

fn gf2_square(square: &mut [u64], mat: &[u64]) {
    for n in 0..mat.len() {
        square[n] = gf2_times(mat, mat[n]);
    }
}

/// The CRC of `A || B` from `crc(A)`, `crc(B)` and `len(B)` (zlib's crc32_combine, for any
/// reflected CRC with matching init and final XOR, given its reflected polynomial and width).
fn crc_combine(crc1: u64, crc2: u64, mut len2: u64, poly: u64, width: usize) -> u64 {
    if len2 == 0 {
        return crc1;
    }
    let mut even = vec![0u64; width];
    let mut odd = vec![0u64; width];
    // The operator for one zero bit.
    odd[0] = poly;
    let mut row = 1u64;
    for o in odd.iter_mut().skip(1) {
        *o = row;
        row <<= 1;
    }
    gf2_square(&mut even, &odd); // two zero bits
    gf2_square(&mut odd, &even); // four zero bits
    let mut crc1 = crc1;
    loop {
        gf2_square(&mut even, &odd); // one zero byte, then 4, 16, ...
        if len2 & 1 == 1 {
            crc1 = gf2_times(&even, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
        gf2_square(&mut odd, &even);
        if len2 & 1 == 1 {
            crc1 = gf2_times(&odd, crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1 ^ crc2
}

fn decode(algo: ChecksumAlgo, v: &str) -> Option<Vec<u8>> {
    let raw = unbase64(v.trim())?;
    let want = match algo {
        ChecksumAlgo::Crc32 | ChecksumAlgo::Crc32c => 4,
        ChecksumAlgo::Crc64Nvme => 8,
        ChecksumAlgo::Sha1 => 20,
        ChecksumAlgo::Sha256 => 32,
    };
    (raw.len() == want).then_some(raw)
}

/// The object's checksum from its parts' (checksum, length).
pub fn combine(algo: ChecksumAlgo, kind: Kind, parts: &[(&str, u64)]) -> Option<String> {
    let raw: Vec<Vec<u8>> = parts.iter().map(|(v, _)| decode(algo, v)).collect::<Option<_>>()?;
    match kind {
        Kind::Composite => {
            let mut h = crate::io::ChecksumHasher::new(algo);
            for r in &raw {
                h.update(r);
            }
            Some(format!("{}-{}", h.finish(), parts.len()))
        }
        Kind::FullObject => {
            let (poly, width) = match algo {
                ChecksumAlgo::Crc32 => (0xEDB8_8320, 32),
                ChecksumAlgo::Crc32c => (0x82F6_3B78, 32),
                ChecksumAlgo::Crc64Nvme => (0x9A6C_9329_AC4B_C9B5, 64),
                _ => return None,
            };
            let as_u64 = |r: &[u8]| r.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            let mut crc = as_u64(&raw[0]);
            for (r, (_, len)) in raw.iter().zip(parts).skip(1) {
                crc = crc_combine(crc, as_u64(r), *len, poly, width);
            }
            Some(base64(&crc.to_be_bytes()[8 - width / 8..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sum(algo: ChecksumAlgo, data: &[u8]) -> String {
        let mut h = crate::io::ChecksumHasher::new(algo);
        h.update(data);
        h.finish()
    }

    /// The vectors from Ceph's s3-tests (three 5 MiB parts of 'A', 'B' and 'C').
    #[test]
    fn s3_tests_vectors() {
        let size = 5 << 20;
        let parts: Vec<Vec<u8>> = b"ABC".iter().map(|c| vec![*c; size]).collect();
        for (algo, kind, want_parts, want) in [
            (ChecksumAlgo::Crc32, Kind::FullObject, ["JRTCyQ==", "QoZTGg==", "YAgjqw=="], "WgDhBQ=="),
            (ChecksumAlgo::Crc32c, Kind::FullObject, ["MDaLrw==", "TH4EZg==", "Z7mBIQ=="], "xU+Krw=="),
            (ChecksumAlgo::Crc64Nvme, Kind::FullObject, ["L/E4WYn8v98=", "xW1l19VobYM=", "cK5MnNaWrW4="], "i+6LR0y3eFo="),
            (
                ChecksumAlgo::Sha256,
                Kind::Composite,
                [
                    "275VF5loJr1YYawit0XSHREhkFXYkkPKGuoK0x9VKxI=",
                    "mrHwOfjTL5Zwfj74F05HOQGLdUb7E5szdCbxgUSq6NM=",
                    "Vw7oB/nKQ5xWb3hNgbyfkvDiivl+U+/Dft48nfJfDow=",
                ],
                "uWBwpe1dxI4Vw8Gf0X9ynOdw/SS6VBzfWm9giiv1sf4=-3",
            ),
        ] {
            let sums: Vec<String> = parts.iter().map(|p| sum(algo, p)).collect();
            assert_eq!(sums, want_parts, "{algo:?}");
            let refs: Vec<(&str, u64)> = sums.iter().map(|s| (s.as_str(), size as u64)).collect();
            assert_eq!(combine(algo, kind, &refs).unwrap(), want, "{algo:?}");
            if kind == Kind::FullObject {
                // A full-object checksum is the checksum of the whole object.
                assert_eq!(sum(algo, &parts.concat()), want, "{algo:?}");
            }
        }
    }

    #[test]
    fn combining_matches_whole_crcs() {
        let data: Vec<u8> = (0..100_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
        for algo in [ChecksumAlgo::Crc32, ChecksumAlgo::Crc32c, ChecksumAlgo::Crc64Nvme] {
            for cuts in [vec![1], vec![0, 5, 99_999], vec![17, 4096, 60_000]] {
                let mut bounds = vec![0];
                bounds.extend(cuts.iter().copied());
                bounds.push(data.len());
                let sums: Vec<(String, u64)> =
                    bounds.windows(2).map(|w| (sum(algo, &data[w[0]..w[1]]), (w[1] - w[0]) as u64)).collect();
                let refs: Vec<(&str, u64)> = sums.iter().map(|(s, n)| (s.as_str(), *n)).collect();
                assert_eq!(combine(algo, Kind::FullObject, &refs).unwrap(), sum(algo, &data), "{algo:?} {cuts:?}");
            }
        }
        assert_eq!(Kind::for_algo(ChecksumAlgo::Sha256, Some(Kind::FullObject)), None);
        assert_eq!(Kind::for_algo(ChecksumAlgo::Crc64Nvme, None), Some(Kind::FullObject));
        assert_eq!(Kind::of("abc-3"), Kind::Composite);
    }
}
