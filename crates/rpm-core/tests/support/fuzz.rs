pub struct SplitMix64(pub u64);
impl SplitMix64 {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    pub fn index(&mut self, n: usize) -> usize {
        assert!(n > 0, "SplitMix64::index requires non-zero bound");
        (self.next() % n as u64) as usize
    }
    pub fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            *x = self.next() as u8;
        }
    }
}
pub fn corpus(mut run: impl FnMut(usize, &mut SplitMix64)) {
    fn env(name: &str, default: u64) -> u64 {
        match std::env::var(name) {
            Ok(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    default
                } else if let Some(hex) = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                {
                    u64::from_str_radix(hex, 16)
                        .unwrap_or_else(|e| panic!("invalid hex env {name}={trimmed:?}: {e}"))
                } else {
                    trimmed
                        .parse()
                        .unwrap_or_else(|e| panic!("invalid integer env {name}={trimmed:?}: {e}"))
                }
            }
            Err(_) => default,
        }
    }
    let seed = env("RPM_FUZZ_SEED", 0x52fe2026);
    let iters = usize::try_from(env("RPM_FUZZ_ITERS", 300))
        .expect("RPM_FUZZ_ITERS exceeds platform usize::MAX");
    assert!(iters > 0, "RPM_FUZZ_ITERS must be greater than zero");
    println!("seed={seed} iterations={iters}");
    let mut rng = SplitMix64(seed);
    for iter in 0..iters {
        if let Err(err) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(iter, &mut rng)))
        {
            panic!(
                "seed={seed} iter={iter}: {}",
                err.downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| err.downcast_ref::<&str>().copied())
                    .unwrap_or("panic")
            );
        }
    }
}
