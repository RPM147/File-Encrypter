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
        std::env::var(name).map_or(default, |s| {
            if let Some(hex) = s.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).unwrap()
            } else {
                s.parse().unwrap()
            }
        })
    }
    let seed = env("RPM_FUZZ_SEED", 0x52fe2026);
    let iters = env("RPM_FUZZ_ITERS", 300);
    assert!(iters > 0);
    println!("seed={seed} iterations={iters}");
    let mut rng = SplitMix64(seed);
    for iter in 0..iters as usize {
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
