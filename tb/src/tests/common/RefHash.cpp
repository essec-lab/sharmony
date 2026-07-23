///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////
//
// SHA-2 + Keccak golden model. See RefHash.hpp for the interface.
//
// Implementations are compact, self-contained references written from the
// specs (FIPS 180-4 for SHA-2, FIPS 202 for SHA-3/SHAKE). They are validated
// by refHashSelfTest() against hardcoded FIPS known-answer values.
//
///////////////////////////////////////////////////////////////////////////////////////

#include "RefHash.hpp"

#include <cstdio>
#include <cstring>
#include <stdexcept>

namespace sharmony {
namespace {

//-------------------------------------------------------------------------------------
//  SHA-256 core (also SHA-224: same core, different IV + truncation).
//-------------------------------------------------------------------------------------
inline uint32_t ror32(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

std::vector<uint8_t> sha256core(const std::vector<uint8_t>& msg,
                                const uint32_t iv[8], size_t out_bytes) {
    uint32_t h[8];
    std::memcpy(h, iv, sizeof(h));

    std::vector<uint8_t> m = msg;
    uint64_t bitlen = (uint64_t)msg.size() * 8;
    m.push_back(0x80);
    while (m.size() % 64 != 56) m.push_back(0x00);
    for (int i = 7; i >= 0; --i) m.push_back((uint8_t)(bitlen >> (8 * i)));

    for (size_t off = 0; off < m.size(); off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = ((uint32_t)m[off + 4*i] << 24) | ((uint32_t)m[off + 4*i + 1] << 16)
                 | ((uint32_t)m[off + 4*i + 2] << 8) | (uint32_t)m[off + 4*i + 3];
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror32(w[i-15],7) ^ ror32(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror32(w[i-2],17) ^ ror32(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror32(e,6) ^ ror32(e,11) ^ ror32(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
            uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    std::vector<uint8_t> out;
    for (int i = 0; i < 8; ++i)
        for (int j = 3; j >= 0; --j) out.push_back((uint8_t)(h[i] >> (8 * j)));
    out.resize(out_bytes);
    return out;
}

//-------------------------------------------------------------------------------------
//  SHA-512 core (also SHA-384 / SHA-512-224 / SHA-512-256: IV + truncation).
//-------------------------------------------------------------------------------------
inline uint64_t ror64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

const uint64_t K512[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL};

std::vector<uint8_t> sha512core(const std::vector<uint8_t>& msg,
                                const uint64_t iv[8], size_t out_bytes) {
    uint64_t h[8];
    std::memcpy(h, iv, sizeof(h));

    std::vector<uint8_t> m = msg;
    uint64_t bitlen = (uint64_t)msg.size() * 8;   // 128-bit length; hi bits are 0 here
    m.push_back(0x80);
    while (m.size() % 128 != 112) m.push_back(0x00);
    for (int i = 0; i < 8; ++i) m.push_back(0x00);              // high 64 bits of length
    for (int i = 7; i >= 0; --i) m.push_back((uint8_t)(bitlen >> (8 * i)));

    for (size_t off = 0; off < m.size(); off += 128) {
        uint64_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = 0;
            for (int j = 0; j < 8; ++j) w[i] = (w[i] << 8) | m[off + 8*i + j];
        }
        for (int i = 16; i < 80; ++i) {
            uint64_t s0 = ror64(w[i-15],1) ^ ror64(w[i-15],8) ^ (w[i-15] >> 7);
            uint64_t s1 = ror64(w[i-2],19) ^ ror64(w[i-2],61) ^ (w[i-2] >> 6);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint64_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 80; ++i) {
            uint64_t S1 = ror64(e,14) ^ ror64(e,18) ^ ror64(e,41);
            uint64_t ch = (e & f) ^ (~e & g);
            uint64_t t1 = hh + S1 + ch + K512[i] + w[i];
            uint64_t S0 = ror64(a,28) ^ ror64(a,34) ^ ror64(a,39);
            uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint64_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d; h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    std::vector<uint8_t> out;
    for (int i = 0; i < 8; ++i)
        for (int j = 7; j >= 0; --j) out.push_back((uint8_t)(h[i] >> (8 * j)));
    out.resize(out_bytes);
    return out;
}

//-------------------------------------------------------------------------------------
//  Keccak-f[1600] sponge (SHA-3 and SHAKE).
//-------------------------------------------------------------------------------------
const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL};

const int KECCAK_ROT[24] = {1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44};
const int KECCAK_PIL[24] = {10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1};

void keccakf(uint64_t st[25]) {
    for (int round = 0; round < 24; ++round) {
        uint64_t bc[5];
        for (int i = 0; i < 5; ++i)
            bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (int i = 0; i < 5; ++i) {
            uint64_t t = bc[(i+4)%5] ^ ror64(bc[(i+1)%5], 63);
            for (int j = 0; j < 25; j += 5) st[j+i] ^= t;
        }
        uint64_t t = st[1];
        for (int i = 0; i < 24; ++i) {
            int j = KECCAK_PIL[i];
            uint64_t tmp = st[j];
            st[j] = ror64(t, 64 - KECCAK_ROT[i]);
            t = tmp;
        }
        for (int j = 0; j < 25; j += 5) {
            uint64_t s[5];
            for (int i = 0; i < 5; ++i) s[i] = st[j+i];
            for (int i = 0; i < 5; ++i) st[j+i] = s[i] ^ (~s[(i+1)%5] & s[(i+2)%5]);
        }
        st[0] ^= KECCAK_RC[round];
    }
}

std::vector<uint8_t> keccak(const std::vector<uint8_t>& msg, size_t rate_bytes,
                            uint8_t domain, size_t out_bytes) {
    uint64_t st[25] = {0};
    uint8_t* stb = reinterpret_cast<uint8_t*>(st);   // little-endian lane bytes

    size_t i = 0;
    while (i + rate_bytes <= msg.size()) {
        for (size_t k = 0; k < rate_bytes; ++k) stb[k] ^= msg[i + k];
        keccakf(st);
        i += rate_bytes;
    }
    // final block with pad10*1
    std::vector<uint8_t> last(rate_bytes, 0);
    size_t rem = msg.size() - i;
    for (size_t k = 0; k < rem; ++k) last[k] = msg[i + k];
    last[rem] ^= domain;
    last[rate_bytes - 1] ^= 0x80;
    for (size_t k = 0; k < rate_bytes; ++k) stb[k] ^= last[k];
    keccakf(st);

    std::vector<uint8_t> out;
    while (out.size() < out_bytes) {
        size_t take = std::min(rate_bytes, out_bytes - out.size());
        for (size_t k = 0; k < take; ++k) out.push_back(stb[k]);
        if (out.size() < out_bytes) keccakf(st);
    }
    return out;
}

// IV tables ------------------------------------------------------------------
const uint32_t IV224[8] = {0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,
                           0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4};
const uint32_t IV256[8] = {0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
const uint64_t IV384[8] = {0xcbbb9d5dc1059ed8ULL,0x629a292a367cd507ULL,0x9159015a3070dd17ULL,
                           0x152fecd8f70e5939ULL,0x67332667ffc00b31ULL,0x8eb44a8768581511ULL,
                           0xdb0c2e0d64f98fa7ULL,0x47b5481dbefa4fa4ULL};
const uint64_t IV512[8] = {0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,
                           0xa54ff53a5f1d36f1ULL,0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,
                           0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL};
const uint64_t IV512_224[8] = {0x8C3D37C819544DA2ULL,0x73E1996689DCD4D6ULL,0x1DFAB7AE32FF9C82ULL,
                               0x679DD514582F9FCFULL,0x0F6D2B697BD44DA8ULL,0x77E36F7304C48942ULL,
                               0x3F9D85A86A1D36C8ULL,0x1112E6AD91D692A1ULL};
const uint64_t IV512_256[8] = {0x22312194FC2BF72CULL,0x9F555FA3C84C64C2ULL,0x2393B86B6F53B151ULL,
                               0x963877195940EABDULL,0x96283EE2A88EFFE3ULL,0xBE5E1E2553863992ULL,
                               0x2B0199FC2C85B8AAULL,0x0EB72DDC81C52CA2ULL};

}  // namespace

std::vector<uint8_t> refHash(Mode mode, const std::vector<uint8_t>& msg, size_t xof_len) {
    switch (mode) {
        case Mode::SHA2_224:     return sha256core(msg, IV224, 28);
        case Mode::SHA2_256:     return sha256core(msg, IV256, 32);
        case Mode::SHA2_384:     return sha512core(msg, IV384, 48);
        case Mode::SHA2_512:     return sha512core(msg, IV512, 64);
        case Mode::SHA2_512_224: return sha512core(msg, IV512_224, 28);
        case Mode::SHA2_512_256: return sha512core(msg, IV512_256, 32);
        case Mode::SHA3_224:     return keccak(msg, 144, 0x06, 28);
        case Mode::SHA3_256:     return keccak(msg, 136, 0x06, 32);
        case Mode::SHA3_384:     return keccak(msg, 104, 0x06, 48);
        case Mode::SHA3_512:     return keccak(msg, 72,  0x06, 64);
        case Mode::SHAKE128:     return keccak(msg, 168, 0x1F, xof_len);
        case Mode::SHAKE256:     return keccak(msg, 136, 0x1F, xof_len);
        default:
            throw std::runtime_error("refHash: unsupported mode");
    }
}

bool refHashSelfTest(std::string* err) {
    struct Kat { Mode m; const char* msg; size_t xof; const char* hex; };
    // Canonical FIPS 180-4 / 202 known-answer values for "abc" and "".
    const Kat kats[] = {
        {Mode::SHA2_224, "abc", 0, "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"},
        {Mode::SHA2_256, "abc", 0, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {Mode::SHA2_384, "abc", 0, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
        {Mode::SHA2_512, "abc", 0, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {Mode::SHA2_512_224, "abc", 0, "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"},
        {Mode::SHA2_512_256, "abc", 0, "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"},
        {Mode::SHA3_224, "", 0, "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"},  // NIST SHA3_224ShortMsg Len=0
        {Mode::SHA3_256, "abc", 0, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"},
        {Mode::SHA3_384, "abc", 0, "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"},
        {Mode::SHA3_512, "abc", 0, "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"},
        {Mode::SHAKE128, "", 32, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"},
        {Mode::SHAKE256, "", 32, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"},
    };
    bool all_ok = true;
    for (const auto& k : kats) {
        std::vector<uint8_t> msg(k.msg, k.msg + std::strlen(k.msg));
        auto got = refHash(k.m, msg, k.xof);
        std::string got_hex = SharmonyDriver::bytesToHex(got);
        if (got_hex != k.hex) {
            all_ok = false;
            std::fprintf(stderr, "[RefHash] KAT MISMATCH mode=0x%x\n  exp %s\n  got %s\n",
                         (unsigned)k.m, k.hex, got_hex.c_str());
            if (err && err->empty())
                *err = std::string("mode 0x?: exp ") + k.hex + " got " + got_hex;
        }
    }
    return all_ok;
}

}  // namespace sharmony
