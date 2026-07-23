///////////////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2025-2026 Universität der Bundeswehr München / FI CODE - ESSEC Lab.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0
//
///////////////////////////////////////////////////////////////////////////////////////

#include "RspParser.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace sharmony {

static std::string trim(const std::string& s) {
    auto a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

std::vector<uint8_t> hexToBytes(const std::string& hex_in) {
    // Allow whitespace inside hex strings; reject odd lengths or bad chars.
    std::string h;
    h.reserve(hex_in.size());
    for (char c : hex_in) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        h.push_back(c);
    }
    if (h.size() % 2 != 0) {
        throw RspParseError("hexToBytes: odd nibble count in '" + hex_in + "'");
    }
    std::vector<uint8_t> out;
    out.reserve(h.size() / 2);
    for (size_t i = 0; i < h.size(); i += 2) {
        int hi = hexVal(h[i]);
        int lo = hexVal(h[i + 1]);
        if (hi < 0 || lo < 0) {
            throw RspParseError("hexToBytes: non-hex char in '" + hex_in + "'");
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// Extract the value part from a "Key = value" line. Returns empty string if
// no '=' present.
static std::string valueAfterEquals(const std::string& line) {
    auto eq = line.find('=');
    if (eq == std::string::npos) return "";
    return trim(line.substr(eq + 1));
}

std::vector<RspVector> parseRsp(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw RspParseError("cannot open .rsp file: " + path);

    std::vector<RspVector> out;
    RspVector cur;
    bool have_len = false;
    bool have_msg = false;

    auto flushIfComplete = [&]() {
        // Vector is complete when we have len, msg, and md.
        if (have_len && have_msg && !cur.md.empty()) {
            out.push_back(cur);
            cur = RspVector{};
            have_len = false;
            have_msg = false;
        }
    };

    std::string raw;
    int lineno = 0;
    while (std::getline(f, raw)) {
        lineno++;
        std::string line = trim(raw);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') continue;   // section header [L = 64], etc.

        // Case-insensitive prefix match on the key.
        std::string key;
        for (char c : line) {
            if (c == '=' || std::isspace(static_cast<unsigned char>(c))) break;
            key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (key == "len") {
            // New vector starts here. If a partial vector is pending without
            // MD, that's a parse error - the file is malformed.
            if (have_len || have_msg) {
                std::ostringstream os;
                os << path << ":" << lineno
                   << ": new 'Len' before previous vector's MD/Output was seen";
                throw RspParseError(os.str());
            }
            std::string v = valueAfterEquals(line);
            try {
                cur.len_bits = std::stoi(v);
            } catch (...) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": malformed Len value '" + v + "'");
            }
            if (cur.len_bits < 0) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": negative Len");
            }
            if (cur.len_bits % 8 != 0) {
                std::ostringstream os;
                os << path << ":" << lineno
                   << ": non-byte-aligned Len = " << cur.len_bits
                   << " is not supported yet";
                throw RspParseError(os.str());
            }
            have_len = true;
        }
        else if (key == "msg") {
            if (!have_len) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": 'Msg' without preceding 'Len'");
            }
            std::string v = valueAfterEquals(line);
            std::vector<uint8_t> bytes = hexToBytes(v);

            if (cur.len_bits == 0) {
                // Convention: Len = 0 with "Msg = 00" represents the empty
                // message. Discard whatever placeholder bytes were given.
                cur.msg.clear();
            } else {
                size_t want = static_cast<size_t>(cur.len_bits / 8);
                if (bytes.size() != want) {
                    std::ostringstream os;
                    os << path << ":" << lineno
                       << ": Msg has " << bytes.size()
                       << " bytes but Len implies " << want;
                    throw RspParseError(os.str());
                }
                cur.msg = std::move(bytes);
            }
            have_msg = true;
        }
        else if (key == "md" || key == "output") {
            if (!have_len || !have_msg) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": MD/Output without complete Len+Msg");
            }
            std::string v = valueAfterEquals(line);
            cur.md = hexToBytes(v);
            flushIfComplete();
        }
        // Other keys (Count, MAC, ...) are silently ignored.
    }

    if (have_len || have_msg) {
        throw RspParseError(path + ": file ends mid-vector (no MD found)");
    }
    if (out.empty()) {
        throw RspParseError(path + ": no vectors found");
    }
    return out;
}

//-------------------------------------------------------------------------------------
// NIST Monte Carlo file parser.
//
// Format:
//   # comments
//   [L = <bytes>]            // optional, ignored
//   Seed = <hex>             // initial seed bytes
//   COUNT = 0                // optional, ignored
//   MD = <hex>               // checkpoint 0
//   COUNT = 1
//   MD = <hex>               // checkpoint 1
//   ...
//
// We ignore COUNT (vectors are stored in file order, which is the canonical
// order) and the [L = ...] header (the digest size is implied by the test).
//-------------------------------------------------------------------------------------
RspMonteFile parseRspMonte(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw RspParseError("cannot open .rsp file: " + path);

    RspMonteFile out;
    bool have_seed = false;
    int  lineno = 0;
    std::string raw;

    while (std::getline(f, raw)) {
        lineno++;
        std::string line = trim(raw);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') continue;   // section header

        // Case-insensitive key extraction.
        std::string key;
        for (char c : line) {
            if (c == '=' || std::isspace(static_cast<unsigned char>(c))) break;
            key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        if (key == "seed") {
            if (have_seed) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": duplicate Seed");
            }
            try {
                out.seed = hexToBytes(valueAfterEquals(line));
            } catch (const RspParseError& e) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": malformed Seed (" + e.what() + ")");
            }
            have_seed = true;
        }
        else if (key == "md" || key == "output") {
            if (!have_seed) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": MD before Seed (is this a Monte file?)");
            }
            try {
                out.checkpoints.push_back(hexToBytes(valueAfterEquals(line)));
            } catch (const RspParseError& e) {
                throw RspParseError(path + ":" + std::to_string(lineno) +
                                    ": malformed MD (" + e.what() + ")");
            }
        }
        // Silently ignore: COUNT, Len, Msg (Monte files rarely have these),
        // and any other keys.
    }

    if (!have_seed) {
        throw RspParseError(path + ": no Seed found (is this really a Monte file?)");
    }
    if (out.checkpoints.empty()) {
        throw RspParseError(path + ": no MD checkpoints found");
    }
    return out;
}

//-------------------------------------------------------------------------------------
// cSHAKE (NIST SP 800-185) file parser.
//
// Each record is:
//   N         = <ascii>      // function-name string (may be empty)
//   S         = <ascii>      // customization string (may be empty)
//   MsgLen    = <int bits>
//   Msg       = <hex>
//   OutputLen = <int bits>
//   Output    = <hex>        // record terminator
//
// N and S are literal ASCII (not hex). A record is flushed when Output is seen.
//-------------------------------------------------------------------------------------
std::vector<CShakeRspVector> parseRspCShake(const std::string& path) {
    std::ifstream f(path);
    if (!f) throw RspParseError("cannot open .rsp file: " + path);

    std::vector<CShakeRspVector> out;
    CShakeRspVector cur;
    bool have_msglen = false, have_msg = false, have_outlen = false;
    int  index = 0;
    int  lineno = 0;
    std::string raw;

    auto fail = [&](const std::string& m) {
        throw RspParseError(path + ":" + std::to_string(lineno) + ": " + m);
    };

    while (std::getline(f, raw)) {
        lineno++;
        std::string line = trim(raw);
        if (line.empty()) continue;
        if (line[0] == '#') continue;
        if (line[0] == '[') continue;   // section header

        std::string key;
        for (char c : line) {
            if (c == '=' || std::isspace(static_cast<unsigned char>(c))) break;
            key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        const std::string v = valueAfterEquals(line);

        if (key == "n") {
            cur.N = v;
        }
        else if (key == "s") {
            cur.S = v;
        }
        else if (key == "msglen") {
            try { cur.msg_len_bits = std::stoi(v); }
            catch (...) { fail("malformed MsgLen '" + v + "'"); }
            if (cur.msg_len_bits < 0)    fail("negative MsgLen");
            if (cur.msg_len_bits % 8 != 0) fail("non-byte-aligned MsgLen");
            have_msglen = true;
        }
        else if (key == "msg") {
            if (!have_msglen) fail("'Msg' without preceding 'MsgLen'");
            std::vector<uint8_t> bytes = hexToBytes(v);
            if (cur.msg_len_bits == 0) {
                cur.msg.clear();   // empty-message convention
            } else {
                size_t want = static_cast<size_t>(cur.msg_len_bits / 8);
                if (bytes.size() != want)
                    fail("Msg has " + std::to_string(bytes.size()) +
                         " bytes but MsgLen implies " + std::to_string(want));
                cur.msg = std::move(bytes);
            }
            have_msg = true;
        }
        else if (key == "outputlen") {
            try { cur.output_len_bits = std::stoi(v); }
            catch (...) { fail("malformed OutputLen '" + v + "'"); }
            if (cur.output_len_bits <= 0)   fail("non-positive OutputLen");
            if (cur.output_len_bits % 8 != 0) fail("non-byte-aligned OutputLen");
            have_outlen = true;
        }
        else if (key == "output") {
            if (!have_msg || !have_outlen)
                fail("Output without complete MsgLen+Msg+OutputLen");
            cur.output = hexToBytes(v);
            size_t want = static_cast<size_t>(cur.output_len_bits / 8);
            if (cur.output.size() != want)
                fail("Output has " + std::to_string(cur.output.size()) +
                     " bytes but OutputLen implies " + std::to_string(want));
            cur.index = index++;
            out.push_back(cur);
            cur = CShakeRspVector{};
            have_msglen = have_msg = have_outlen = false;
        }
        // Other keys (Count, ...) are silently ignored.
    }

    if (have_msglen || have_msg || have_outlen)
        throw RspParseError(path + ": file ends mid-record (no Output found)");
    if (out.empty())
        throw RspParseError(path + ": no vectors found");
    return out;
}

}  // namespace sharmony
