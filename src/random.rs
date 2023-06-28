// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

use crate::crypto::sha512::CSHA512;
use crate::crypto::sha256::CSHA256;
use crate::time::GetTimeMicros;
use crate::crypto::Hasher;
use crate::crypto::common::ReadLE64;
use crate::logging::BCLog;
use crate::LogPrint;
use rand::Rng;
use std::sync::Mutex;
use std::mem::size_of_val;
use std::arch::asm;

fn GetPerformanceCounter() -> u64 {
    let (low, high): (u32, u32);
    unsafe {
        asm!(
            "rdtsc",
            out("eax") low,
            out("edx") high,
        );
    }
    ((high as u64) << 32) | (low as u64)
}


//#[cfg(feature = "getcpuid")]
static g_rdrand_supported: bool = false;
static g_rdseed_supported: bool = false;
static CPUID_F1_ECX_RDRAND: u32 = 0x40000000;
static CPUID_F7_EBX_RDSEED: u32 = 0x00040000;

/* 
fn InitHardwareRand()
{
    // TODO: implement GetCPUID
 /*    let (eax, ebx, ecx, edx) = (0u32, 0u32, 0u32, 0u32);
    GetCPUID(1, 0, eax, ebx, ecx, edx);
    if (ecx & CPUID_F1_ECX_RDRAND) {
        g_rdrand_supported = true;
    }
    GetCPUID(7, 0, eax, ebx, ecx, edx);
    if (ebx & CPUID_F7_EBX_RDSEED) {
        g_rdseed_supported = true;
    } */
} */

///
///  Read 64 bits of entropy using rdrand.
///
/// Must only be called when RdRand is supported.
///
fn GetRdRand() -> u64 {
    let mut ok: u8;
    let mut r1: u64 = 0;

    // RdRand may very rarely fail. Invoke it up to 10 times in a loop to reduce this risk.
    for i in 0..10 {
        unsafe {
            asm!(
            "rdrand rax",
            "setc cl",
            out("rax") r1,
            out("cl") ok,
            options(nostack, preserves_flags),
        ); // rdseed %rax

        }
        if ok != 0 {
            break;
        }
    }
    r1
}

/// Read 64 bits of entropy using rdseed.
///
/// Must only be called when RdSeed is supported.
///
fn GetRdSeed() -> u64 {
    let mut ok: u8;
    let mut r1: u64 = 0;

    loop {
        unsafe {
            asm!(
            "rdseed rax",
            "setc cl",
            out("rax") r1,
            out("cl") ok,
            options(nostack, preserves_flags),
        ); // rdseed %rax

        }
        if ok != 0 {
            break;
        }
    }
    r1
}

struct RNGState {
    m_mutex: Mutex<()>,
    /* The RNG state consists of 256 bits of entropy, taken from the output of
     * one operation's SHA512 output, and fed as input to the next one.
     * Carrying 256 bits of entropy should be sufficient to guarantee
     * unpredictability as long as any entropy source was ever unpredictable
     * to an attacker. To protect against situations where an attacker might
     * observe the RNG's state, fresh entropy is always mixed when
     * GetStrongRandBytes is called.
     */
    m_state: [u8; 32],
    m_counter: u64,
    m_strongly_seeded: bool,
    m_events_mutex: Mutex<()>,
    m_events_hasher: CSHA256,
}

impl RNGState {

    pub fn new() -> Self
    {
        //InitHardwareRand();
        Self {
            m_counter: 0,
            m_mutex: Mutex::new(()),
            m_strongly_seeded: false,
            m_state: [0; 32],
            m_events_mutex: Mutex::new(()),
            m_events_hasher: CSHA256::new()
        }
    }


    //void AddEvent(uint32_t event_info) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_events_mutex)
    pub fn AddEvent(&mut self, event_info: u32)
    {
        let _m = self.m_events_mutex.lock().unwrap();

        self.m_events_hasher.Write(
            &event_info.to_le_bytes()[..],
            size_of_val(&event_info)
        );
        // Get the low four bytes of the performance counter. This translates to roughly the
        // subsecond part.
        let perfcounter = GetPerformanceCounter() & 0xffffffff;
        self.m_events_hasher.Write(&perfcounter.to_le_bytes()[..], size_of_val(&perfcounter));
    }

    /**
     * Feed (the hash of) all events added through AddEvent() to hasher.
     */
    //void SeedEvents(CSHA512& hasher) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_events_mutex)
    pub fn SeedEvents(&mut self, hasher: &mut CSHA512)
    {
        // We use only SHA256 for the events hashing to get the ASM speedups we have for SHA256,
        // since we want it to be fast as network peers may be able to trigger it repeatedly.
        let _m = self.m_events_mutex.lock().unwrap();

        let mut events_hash: [u8; 32] = [0; 32];
        self.m_events_hasher.Finalize(&mut events_hash);
        //hasher.Write(events_hash, 32);
        hasher.Write(&mut events_hash[..], 32);

        // Re-initialize the hasher with the finalized state to use later.
        self.m_events_hasher.Reset();
        self.m_events_hasher.Write(&events_hash[..], 32);
    }

    /** Extract up to 32 bytes of entropy from the RNG state, mixing in new entropy from hasher.
     *
     * If this function has never been called with strong_seed = true, false is returned.
     */
    //bool MixExtract(unsigned char* out, size_t num, CSHA512&& hasher, bool strong_seed) noexcept EXCLUSIVE_LOCKS_REQUIRED(!m_mutex)
    pub fn MixExtract(&mut self, out: &mut [u8], num: usize, hasher: &mut CSHA512, strong_seed: bool) -> bool
    {
        assert!(num <= 32);
        let mut buf: [u8; 64] = [0; 64];
        let ret: bool;

        {
            let _m = self.m_events_mutex.lock().unwrap();
            self.m_strongly_seeded |= strong_seed;
            ret = self.m_strongly_seeded;
            // Write the current state of the RNG into the hasher
            hasher.Write(&mut self.m_state, 32);
            // Write a new counter number into the state
            let mut counter_bytes = self.m_counter.to_le_bytes();
            hasher.Write(&mut counter_bytes, size_of_val(&self.m_counter));
            self.m_counter = ReadLE64(&counter_bytes[..]);
            self.m_counter += 1;
            // Finalize the hasher
            hasher.Finalize(&mut buf[..]);
            // Store the last 32 bytes of the hash output as new RNG state.
            //memcpy(m_state, buf + 32, 32);
            self.m_state.copy_from_slice(&buf[32..64]);
        }
        // If desired, copy (up to) the first 32 bytes of the hash output as output.
        if num > 0 {
            //memcpy(out, buf, num);
            out.copy_from_slice(&buf[..num]);
        }
        // Best effort cleanup of internal state
        hasher.Reset();
        //memory_cleanse(buf, 64);
        buf = [0; 64];

        return ret;
    }
}

enum RNGLevel {
    FAST, // Automatically called by GetRandBytes
    SLOW, // Automatically called by GetStrongRandBytes
    PERIODIC, // Called by RandAddPeriodic()
}

fn GetOSRand(buffer: &mut [u8])
{
    let mut rng = rand::thread_rng();
    rng.fill(buffer);
}

//static void SeedTimestamp(CSHA512& hasher) noexcept
fn SeedTimestamp(hasher: &mut CSHA512)
{
    let perfcounter = GetPerformanceCounter();
    hasher.Write(&mut perfcounter.to_le_bytes(), size_of_val(&perfcounter));
}

/** Add 64 bits of entropy gathered from hardware to hasher. Do nothing if not supported. */
/* static void SeedHardwareFast(CSHA512& hasher) noexcept {
    #if defined(__x86_64__) || defined(__amd64__) || defined(__i386__)
        if (g_rdrand_supported) {
            uint64_t out = GetRdRand();
            hasher.Write((const unsigned char*)&out, sizeof(out));
            return;
        }
    #endif
} */

fn SeedHardwareFast(hasher: &mut CSHA512)
{
    let mut buffer:[u8; 8] = [0; 8];
    let len = buffer.len();

    hasher.Write(&mut buffer[..], len);
}

/** Add 256 bits of entropy gathered from hardware to hasher. Do nothing if not supported. */
//static void SeedHardwareSlow(CSHA512& hasher) noexcept {
fn SeedHardwareSlow(hasher: &mut CSHA512) {
    // When we want 256 bits of entropy, prefer RdSeed over RdRand, as it's
    // guaranteed to produce independent randomness on every call.
    if g_rdseed_supported {
        for i in [0..4] {
            let mut out = GetRdSeed();
            hasher.Write(&mut out.to_le_bytes(), size_of_val(&out));
        }
        return;
    }
    // When falling back to RdRand, XOR the result of 1024 results.
    // This guarantees a reseeding occurs between each.
    if g_rdrand_supported {
        for i in [0..4] {
            let mut out: u64 = 0;
            for j in [0..1024] { out ^= GetRdRand(); }
            hasher.Write(&mut out.to_le_bytes(), size_of_val(&out));
        }
        return;
    }
}
    
    /** Use repeated SHA512 to strengthen the randomness in seed32, and feed into hasher. */
    //static void Strengthen(const unsigned char (&seed)[32], int microseconds, CSHA512& hasher) noexcept
    fn Strengthen(seed: &mut [u8; 32], microseconds: i32, hasher: &mut CSHA512)
    {
        let mut inner_hasher = CSHA512::new();
        let len = seed.len();
        inner_hasher.Write(&mut seed[..], len);
    
        // Hash loop
        let mut buffer:[u8; 64] = [0; 64];
        let stop: i64 = GetTimeMicros() + microseconds as i64;
        loop {
            for _i in [0..1000] {
                inner_hasher.Finalize(&mut buffer[..]);
                inner_hasher.Reset();
                let len = buffer.len();
                inner_hasher.Write(&mut buffer[..], len);
            }
            // Benchmark operation and feed it into outer hasher.
            let mut perf = GetPerformanceCounter();
            hasher.Write(&mut perf.to_le_bytes(), size_of_val(&perf));
            if GetTimeMicros() < stop { break; }
        }
    
        // Produce output from inner state and feed it to outer hasher.
        inner_hasher.Finalize(&mut buffer[..]);
        let len = buffer.len();
        hasher.Write(&mut buffer[..], len);
        // Try to clean up.
        inner_hasher.Reset();
        //memory_cleanse(buffer, sizeof(buffer));
        buffer = [0; 64];
    }


fn SeedFast(hasher: &mut CSHA512)
{
    let mut buffer:[u8; 32] = [0; 32];

    // Stack pointer to indirectly commit to thread/callstack
    //const unsigned char* ptr = buffer;
    let len = buffer.len();
    hasher.Write(&mut buffer[..], len);

    // Hardware randomness is very fast when available; use it always.
    SeedHardwareFast(hasher);

    // High-precision timestamp
    SeedTimestamp(hasher);
}

fn SeedSlow(hasher: &mut CSHA512, rng: &mut RNGState)
{
    let mut buffer:[u8; 32] = [0; 32];

    // Everything that the 'fast' seeder includes
    SeedFast(hasher);

    // OS randomness
    GetOSRand(&mut buffer[..]);

    let len = buffer.len();
    hasher.Write(&mut buffer[..], len);

    // Add the events hasher into the mix
    rng.SeedEvents(hasher);

    // High-precision timestamp.
    //
    // Note that we also commit to a timestamp in the Fast seeder, so we indirectly commit to a
    // benchmark of all the entropy gathering sources in this function).
    SeedTimestamp(hasher);
}

/** Extract entropy from rng, strengthen it, and feed it into hasher. */
//static void SeedStrengthen(CSHA512& hasher, RNGState& rng, int microseconds) noexcept
fn SeedStrengthen(hasher: &mut CSHA512, rng: &mut RNGState, microseconds: i32)
{
    // Generate 32 bytes of entropy from the RNG, and a copy of the entropy already in hasher.
    let mut strengthen_seed:[u8; 32] = [0; 32];
    let len = strengthen_seed.len();
    rng.MixExtract(&mut strengthen_seed, len, hasher, false);
    
    // Strengthen the seed, and feed it into hasher.
    Strengthen(&mut strengthen_seed, microseconds, hasher);
}

//static void SeedPeriodic(CSHA512& hasher, RNGState& rng) noexcept
fn SeedPeriodic(hasher: &mut CSHA512, rng: &mut RNGState)
{
    // Everything that the 'fast' seeder includes
    SeedFast(hasher);

    // High-precision timestamp
    SeedTimestamp(hasher);

    // Add the events hasher into the mix
    rng.SeedEvents(hasher);

    // Dynamic environment data (performance monitoring, ...)
    let old_size = hasher.Size();
    // TODO:
    //RandAddDynamicEnv(hasher);
    LogPrint!(BCLog::RAND, "Feeding {} bytes of dynamic environment data into RNG\n", hasher.Size() - old_size);

    // Strengthen for 10 ms
    SeedStrengthen(hasher, rng, 10000);
}

//static void SeedStartup(CSHA512& hasher, RNGState& rng) noexcept
fn SeedStartup(hasher: &mut CSHA512, rng: &mut RNGState)
{
    // Gather 256 bits of hardware randomness, if available
    SeedHardwareSlow(hasher);

    // Everything that the 'slow' seeder includes.
    SeedSlow(hasher, rng);

    // Dynamic environment data (performance monitoring, ...)
    let old_size = hasher.Size();
    // TODO:
    //RandAddDynamicEnv(hasher);

    // Static environment data
    // TODO:
    //RandAddStaticEnv(hasher);
    LogPrint!(BCLog::RAND, "Feeding {} bytes of environment data into RNG\n", hasher.Size() - old_size);

    // Strengthen for 100 ms
    SeedStrengthen(hasher, rng, 100000);
}

fn ProcRand(out: &mut [u8], num: usize, level: RNGLevel)
{
    // Make sure the RNG is initialized first (as all Seed* function possibly need hwrand to be available).
    let mut rng = RNGState::new();

    assert!(!num <= 32);

    let mut hasher: CSHA512 = CSHA512::new();
    match level {
        RNGLevel::FAST => SeedFast(&mut hasher),
        RNGLevel::SLOW => SeedSlow(&mut hasher, &mut rng),
        RNGLevel::PERIODIC => SeedPeriodic(&mut hasher, &mut rng),
    }

    // Combine with and update state
    if !rng.MixExtract(out, num, &mut hasher, false) {
        // On the first invocation, also seed with SeedStartup().
        let mut startup_hasher: CSHA512 = CSHA512::new();
        SeedStartup(&mut startup_hasher, &mut rng);
        rng.MixExtract(out, num, &mut startup_hasher, true);
    }
}

// void GetStrongRandBytes(Span<unsigned char> bytes) noexcept { ProcRand(bytes.data(), bytes.size(), RNGLevel::SLOW); }
pub fn GetStrongRandBytes(bytes: &mut [u8]) { ProcRand(bytes, bytes.len(), RNGLevel::SLOW); }