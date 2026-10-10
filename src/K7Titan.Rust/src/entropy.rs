pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &c in counts.iter() {
        if c == 0 {
            continue;
        }
        let p = c as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_data_has_zero_entropy() {
        let data = vec![0x41u8; 4096];
        assert!(shannon_entropy(&data) < 0.0001);
    }

    #[test]
    fn two_symbols_give_one_bit() {
        let mut data = vec![0u8; 1024];
        for i in 512..1024 {
            data[i] = 1;
        }
        assert!((shannon_entropy(&data) - 1.0).abs() < 0.0001);
    }

    #[test]
    fn empty_is_zero() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }
}
