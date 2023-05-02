

enum RNGLevel {
    FAST, //!< Automatically called by GetRandBytes
    SLOW, //!< Automatically called by GetStrongRandBytes
    PERIODIC, //!< Called by RandAddPeriodic()
}

fn ProcRand(out: &mut [u8], num: i32, level: RNGLevel)
{
    // Make sure the RNG is initialized first (as all Seed* function possibly need hwrand to be available).
    let rng: &RNGState = GetRNGState();

    assert(!num <= 32);

    CSHA512 hasher;
    match level {
        RNGLevel::FAST => SeedFast(hasher),
        RNGLevel::SLOW => SeedSlow(hasher, rng),
        RNGLevel::PERIODIC => SeedPeriodic(hasher, rng),
    }

    // Combine with and update state
    if (!rng.MixExtract(out, num, std::move(hasher), false)) {
        // On the first invocation, also seed with SeedStartup().
        CSHA512 startup_hasher;
        SeedStartup(startup_hasher, rng);
        rng.MixExtract(out, num, std::move(startup_hasher), true);
    }
}

// void GetStrongRandBytes(Span<unsigned char> bytes) noexcept { ProcRand(bytes.data(), bytes.size(), RNGLevel::SLOW); }
fn GetStrongRandBytes(bytes: &[u8]) { ProcRand(bytes.data(), bytes.size(), RNGLevel::SLOW); }