// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/// Amount in satoshis (Can be negative)
// typedef int64_t CAmount;
pub type CAmount = i64;

/** The amount of satoshis in one BTC. */
pub const COIN: CAmount = 100000000;

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
pub const MAX_MONEY: CAmount = 21000000 * COIN;

fn MoneyRange(nValue: &CAmount) -> bool
{
    nValue >= 0 && nValue <= MAX_MONEY
}
