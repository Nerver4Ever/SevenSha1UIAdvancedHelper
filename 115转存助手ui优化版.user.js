// ==UserScript==
// @name         115转存助手ui优化版
// @name:zh      115转存助手ui优化版
// @description  2022.08.16 更新，115转存助手ui优化版 v3.7 (143.2022.0816.1)(based on Fake115Upload 1.4.3 @T3rry)
// @author       Never4Ever
// @namespace    Fake115Upload@Never4Ever
// @version      143.2022.0816.1
// @match        https://115.com/*
// @exclude      https://115.com/s/*

// @grant        GM_xmlhttpRequest
// @grant        GM_log
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_setClipboard
// @grant        unsafeWindow
// @grant        GM_registerMenuCommand
// @grant        GM_addStyle
// @grant        GM_info

// @connect      proapi.115.com
// @connect      webapi.115.com
// @connect      115.com

// @require      https://unpkg.zhimg.com/underscore@1.12.0/underscore-min.js
// @require      https://unpkg.zhimg.com/sweetalert2@11.3.0
// @require      https://unpkg.zhimg.com/node-forge@0.10.0/dist/forge.min.js
// @require      https://unpkg.zhimg.com/emoutils@2.0.0/dist/umd/emoutils.min.js
// ==/UserScript==


/*********************************************
请从以下获取最新版，或者遇到问题去此反馈，感谢
https://github.com/Nerver4Ever/SevenSha1UIAdvancedHelper
**********************************************/

/*针对网络问题，只能将不稳定的依赖库放置于此*/

/*jssha@2.3.1/src/sha.js*/
/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-4 and FIPS PUB 202, as well as the corresponding
 HMAC implementation as defined in FIPS PUB 198a

 Copyright Brian Turek 2008-2017
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information

 Several functions taken from Paul Johnston
*/
'use strict';
(function (Y) {
    function C(c, a, b) {
        var e = 0,
            h = [],
            n = 0,
            g, l, d, f, m, q, u, r, I = !1,
            v = [],
            w = [],
            t, y = !1,
            z = !1,
            x = -1;
        b = b || {};
        g = b.encoding || "UTF8";
        t = b.numRounds || 1;
        if (t !== parseInt(t, 10) || 1 > t) throw Error("numRounds must a integer >= 1");
        if ("SHA-1" === c) m = 512, q = K, u = Z, f = 160, r = function (a) {
            return a.slice()
        };
        else if (0 === c.lastIndexOf("SHA-", 0))
            if (q = function (a, b) {
                return L(a, b, c)
            }, u = function (a, b, h, e) {
                var k, f;
                if ("SHA-224" === c || "SHA-256" === c) k = (b + 65 >>> 9 << 4) + 15, f = 16;
                else if ("SHA-384" === c || "SHA-512" === c) k = (b + 129 >>> 10 <<
                    5) + 31, f = 32;
                else throw Error("Unexpected error in SHA-2 implementation");
                for (; a.length <= k;) a.push(0);
                a[b >>> 5] |= 128 << 24 - b % 32;
                b = b + h;
                a[k] = b & 4294967295;
                a[k - 1] = b / 4294967296 | 0;
                h = a.length;
                for (b = 0; b < h; b += f) e = L(a.slice(b, b + f), e, c);
                if ("SHA-224" === c) a = [e[0], e[1], e[2], e[3], e[4], e[5], e[6]];
                else if ("SHA-256" === c) a = e;
                else if ("SHA-384" === c) a = [e[0].a, e[0].b, e[1].a, e[1].b, e[2].a, e[2].b, e[3].a, e[3].b, e[4].a, e[4].b, e[5].a, e[5].b];
                else if ("SHA-512" === c) a = [e[0].a, e[0].b, e[1].a, e[1].b, e[2].a, e[2].b, e[3].a, e[3].b, e[4].a,
                e[4].b, e[5].a, e[5].b, e[6].a, e[6].b, e[7].a, e[7].b
                ];
                else throw Error("Unexpected error in SHA-2 implementation");
                return a
            }, r = function (a) {
                return a.slice()
            }, "SHA-224" === c) m = 512, f = 224;
            else if ("SHA-256" === c) m = 512, f = 256;
            else if ("SHA-384" === c) m = 1024, f = 384;
            else if ("SHA-512" === c) m = 1024, f = 512;
            else throw Error("Chosen SHA variant is not supported");
        else if (0 === c.lastIndexOf("SHA3-", 0) || 0 === c.lastIndexOf("SHAKE", 0)) {
            var F = 6;
            q = D;
            r = function (a) {
                var c = [],
                    e;
                for (e = 0; 5 > e; e += 1) c[e] = a[e].slice();
                return c
            };
            x = 1;
            if ("SHA3-224" ===
                c) m = 1152, f = 224;
            else if ("SHA3-256" === c) m = 1088, f = 256;
            else if ("SHA3-384" === c) m = 832, f = 384;
            else if ("SHA3-512" === c) m = 576, f = 512;
            else if ("SHAKE128" === c) m = 1344, f = -1, F = 31, z = !0;
            else if ("SHAKE256" === c) m = 1088, f = -1, F = 31, z = !0;
            else throw Error("Chosen SHA variant is not supported");
            u = function (a, c, e, b, h) {
                e = m;
                var k = F,
                    f, g = [],
                    n = e >>> 5,
                    l = 0,
                    d = c >>> 5;
                for (f = 0; f < d && c >= e; f += n) b = D(a.slice(f, f + n), b), c -= e;
                a = a.slice(f);
                for (c %= e; a.length < n;) a.push(0);
                f = c >>> 3;
                a[f >> 2] ^= k << f % 4 * 8;
                a[n - 1] ^= 2147483648;
                for (b = D(a, b); 32 * g.length < h;) {
                    a = b[l %
                        5][l / 5 | 0];
                    g.push(a.b);
                    if (32 * g.length >= h) break;
                    g.push(a.a);
                    l += 1;
                    0 === 64 * l % e && D(null, b)
                }
                return g
            }
        } else throw Error("Chosen SHA variant is not supported");
        d = M(a, g, x);
        l = A(c);
        this.setHMACKey = function (a, b, h) {
            var k;
            if (!0 === I) throw Error("HMAC key already set");
            if (!0 === y) throw Error("Cannot set HMAC key after calling update");
            if (!0 === z) throw Error("SHAKE is not supported for HMAC");
            g = (h || {}).encoding || "UTF8";
            b = M(b, g, x)(a);
            a = b.binLen;
            b = b.value;
            k = m >>> 3;
            h = k / 4 - 1;
            if (k < a / 8) {
                for (b = u(b, a, 0, A(c), f); b.length <= h;) b.push(0);
                b[h] &= 4294967040
            } else if (k > a / 8) {
                for (; b.length <= h;) b.push(0);
                b[h] &= 4294967040
            }
            for (a = 0; a <= h; a += 1) v[a] = b[a] ^ 909522486, w[a] = b[a] ^ 1549556828;
            l = q(v, l);
            e = m;
            I = !0
        };
        this.update = function (a) {
            var c, b, k, f = 0,
                g = m >>> 5;
            c = d(a, h, n);
            a = c.binLen;
            b = c.value;
            c = a >>> 5;
            for (k = 0; k < c; k += g) f + m <= a && (l = q(b.slice(k, k + g), l), f += m);
            e += f;
            h = b.slice(f >>> 5);
            n = a % m;
            y = !0
        };
        this.getHash = function (a, b) {
            var k, g, d, m;
            if (!0 === I) throw Error("Cannot call getHash after setting HMAC key");
            d = N(b);
            if (!0 === z) {
                if (-1 === d.shakeLen) throw Error("shakeLen must be specified in options");
                f = d.shakeLen
            }
            switch (a) {
                case "HEX":
                    k = function (a) {
                        return O(a, f, x, d)
                    };
                    break;
                case "B64":
                    k = function (a) {
                        return P(a, f, x, d)
                    };
                    break;
                case "BYTES":
                    k = function (a) {
                        return Q(a, f, x)
                    };
                    break;
                case "ARRAYBUFFER":
                    try {
                        g = new ArrayBuffer(0)
                    } catch (p) {
                        throw Error("ARRAYBUFFER not supported by this environment");
                    }
                    k = function (a) {
                        return R(a, f, x)
                    };
                    break;
                default:
                    throw Error("format must be HEX, B64, BYTES, or ARRAYBUFFER");
            }
            m = u(h.slice(), n, e, r(l), f);
            for (g = 1; g < t; g += 1) !0 === z && 0 !== f % 32 && (m[m.length - 1] &= 16777215 >>> 24 - f % 32), m = u(m, f,
                0, A(c), f);
            return k(m)
        };
        this.getHMAC = function (a, b) {
            var k, g, d, p;
            if (!1 === I) throw Error("Cannot call getHMAC without first setting HMAC key");
            d = N(b);
            switch (a) {
                case "HEX":
                    k = function (a) {
                        return O(a, f, x, d)
                    };
                    break;
                case "B64":
                    k = function (a) {
                        return P(a, f, x, d)
                    };
                    break;
                case "BYTES":
                    k = function (a) {
                        return Q(a, f, x)
                    };
                    break;
                case "ARRAYBUFFER":
                    try {
                        k = new ArrayBuffer(0)
                    } catch (v) {
                        throw Error("ARRAYBUFFER not supported by this environment");
                    }
                    k = function (a) {
                        return R(a, f, x)
                    };
                    break;
                default:
                    throw Error("outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER");
            }
            g = u(h.slice(), n, e, r(l), f);
            p = q(w, A(c));
            p = u(g, f, m, p, f);
            return k(p)
        }
    }

    function b(c, a) {
        this.a = c;
        this.b = a
    }

    function O(c, a, b, e) {
        var h = "";
        a /= 8;
        var n, g, d;
        d = -1 === b ? 3 : 0;
        for (n = 0; n < a; n += 1) g = c[n >>> 2] >>> 8 * (d + n % 4 * b), h += "0123456789abcdef".charAt(g >>> 4 & 15) + "0123456789abcdef".charAt(g & 15);
        return e.outputUpper ? h.toUpperCase() : h
    }

    function P(c, a, b, e) {
        var h = "",
            n = a / 8,
            g, d, p, f;
        f = -1 === b ? 3 : 0;
        for (g = 0; g < n; g += 3)
            for (d = g + 1 < n ? c[g + 1 >>> 2] : 0, p = g + 2 < n ? c[g + 2 >>> 2] : 0, p = (c[g >>> 2] >>> 8 * (f + g % 4 * b) & 255) << 16 | (d >>> 8 * (f + (g + 1) % 4 * b) & 255) << 8 | p >>> 8 * (f +
                (g + 2) % 4 * b) & 255, d = 0; 4 > d; d += 1) 8 * g + 6 * d <= a ? h += "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(p >>> 6 * (3 - d) & 63) : h += e.b64Pad;
        return h
    }

    function Q(c, a, b) {
        var e = "";
        a /= 8;
        var h, d, g;
        g = -1 === b ? 3 : 0;
        for (h = 0; h < a; h += 1) d = c[h >>> 2] >>> 8 * (g + h % 4 * b) & 255, e += String.fromCharCode(d);
        return e
    }

    function R(c, a, b) {
        a /= 8;
        var e, h = new ArrayBuffer(a),
            d, g;
        g = new Uint8Array(h);
        d = -1 === b ? 3 : 0;
        for (e = 0; e < a; e += 1) g[e] = c[e >>> 2] >>> 8 * (d + e % 4 * b) & 255;
        return h
    }

    function N(c) {
        var a = {
            outputUpper: !1,
            b64Pad: "=",
            shakeLen: -1
        };
        c = c || {};
        a.outputUpper = c.outputUpper || !1;
        !0 === c.hasOwnProperty("b64Pad") && (a.b64Pad = c.b64Pad);
        if (!0 === c.hasOwnProperty("shakeLen")) {
            if (0 !== c.shakeLen % 8) throw Error("shakeLen must be a multiple of 8");
            a.shakeLen = c.shakeLen
        }
        if ("boolean" !== typeof a.outputUpper) throw Error("Invalid outputUpper formatting option");
        if ("string" !== typeof a.b64Pad) throw Error("Invalid b64Pad formatting option");
        return a
    }

    function M(c, a, b) {
        switch (a) {
            case "UTF8":
            case "UTF16BE":
            case "UTF16LE":
                break;
            default:
                throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");
        }
        switch (c) {
            case "HEX":
                c = function (a, c, d) {
                    var g = a.length,
                        l, p, f, m, q, u;
                    if (0 !== g % 2) throw Error("String of HEX type must be in byte increments");
                    c = c || [0];
                    d = d || 0;
                    q = d >>> 3;
                    u = -1 === b ? 3 : 0;
                    for (l = 0; l < g; l += 2) {
                        p = parseInt(a.substr(l, 2), 16);
                        if (isNaN(p)) throw Error("String of HEX type contains invalid characters");
                        m = (l >>> 1) + q;
                        for (f = m >>> 2; c.length <= f;) c.push(0);
                        c[f] |= p << 8 * (u + m % 4 * b)
                    }
                    return {
                        value: c,
                        binLen: 4 * g + d
                    }
                };
                break;
            case "TEXT":
                c = function (c, h, d) {
                    var g, l, p = 0,
                        f, m, q, u, r, t;
                    h = h || [0];
                    d = d || 0;
                    q = d >>> 3;
                    if ("UTF8" === a)
                        for (t = -1 ===
                            b ? 3 : 0, f = 0; f < c.length; f += 1)
                            for (g = c.charCodeAt(f), l = [], 128 > g ? l.push(g) : 2048 > g ? (l.push(192 | g >>> 6), l.push(128 | g & 63)) : 55296 > g || 57344 <= g ? l.push(224 | g >>> 12, 128 | g >>> 6 & 63, 128 | g & 63) : (f += 1, g = 65536 + ((g & 1023) << 10 | c.charCodeAt(f) & 1023), l.push(240 | g >>> 18, 128 | g >>> 12 & 63, 128 | g >>> 6 & 63, 128 | g & 63)), m = 0; m < l.length; m += 1) {
                                r = p + q;
                                for (u = r >>> 2; h.length <= u;) h.push(0);
                                h[u] |= l[m] << 8 * (t + r % 4 * b);
                                p += 1
                            } else if ("UTF16BE" === a || "UTF16LE" === a)
                        for (t = -1 === b ? 2 : 0, l = "UTF16LE" === a && 1 !== b || "UTF16LE" !== a && 1 === b, f = 0; f < c.length; f += 1) {
                            g = c.charCodeAt(f);
                            !0 === l && (m = g & 255, g = m << 8 | g >>> 8);
                            r = p + q;
                            for (u = r >>> 2; h.length <= u;) h.push(0);
                            h[u] |= g << 8 * (t + r % 4 * b);
                            p += 2
                        }
                    return {
                        value: h,
                        binLen: 8 * p + d
                    }
                };
                break;
            case "B64":
                c = function (a, c, d) {
                    var g = 0,
                        l, p, f, m, q, u, r, t;
                    if (-1 === a.search(/^[a-zA-Z0-9=+\/]+$/)) throw Error("Invalid character in base-64 string");
                    p = a.indexOf("=");
                    a = a.replace(/\=/g, "");
                    if (-1 !== p && p < a.length) throw Error("Invalid '=' found in base-64 string");
                    c = c || [0];
                    d = d || 0;
                    u = d >>> 3;
                    t = -1 === b ? 3 : 0;
                    for (p = 0; p < a.length; p += 4) {
                        q = a.substr(p, 4);
                        for (f = m = 0; f < q.length; f += 1) l = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(q[f]),
                            m |= l << 18 - 6 * f;
                        for (f = 0; f < q.length - 1; f += 1) {
                            r = g + u;
                            for (l = r >>> 2; c.length <= l;) c.push(0);
                            c[l] |= (m >>> 16 - 8 * f & 255) << 8 * (t + r % 4 * b);
                            g += 1
                        }
                    }
                    return {
                        value: c,
                        binLen: 8 * g + d
                    }
                };
                break;
            case "BYTES":
                c = function (a, c, d) {
                    var g, l, p, f, m, q;
                    c = c || [0];
                    d = d || 0;
                    p = d >>> 3;
                    q = -1 === b ? 3 : 0;
                    for (l = 0; l < a.length; l += 1) g = a.charCodeAt(l), m = l + p, f = m >>> 2, c.length <= f && c.push(0), c[f] |= g << 8 * (q + m % 4 * b);
                    return {
                        value: c,
                        binLen: 8 * a.length + d
                    }
                };
                break;
            case "ARRAYBUFFER":
                try {
                    c = new ArrayBuffer(0)
                } catch (e) {
                    throw Error("ARRAYBUFFER not supported by this environment");
                }
                c =
                    function (a, c, d) {
                        var g, l, p, f, m, q;
                        c = c || [0];
                        d = d || 0;
                        l = d >>> 3;
                        m = -1 === b ? 3 : 0;
                        q = new Uint8Array(a);
                        for (g = 0; g < a.byteLength; g += 1) f = g + l, p = f >>> 2, c.length <= p && c.push(0), c[p] |= q[g] << 8 * (m + f % 4 * b);
                        return {
                            value: c,
                            binLen: 8 * a.byteLength + d
                        }
                    };
                break;
            default:
                throw Error("format must be HEX, TEXT, B64, BYTES, or ARRAYBUFFER");
        }
        return c
    }

    function y(c, a) {
        return c << a | c >>> 32 - a
    }

    function S(c, a) {
        return 32 < a ? (a -= 32, new b(c.b << a | c.a >>> 32 - a, c.a << a | c.b >>> 32 - a)) : 0 !== a ? new b(c.a << a | c.b >>> 32 - a, c.b << a | c.a >>> 32 - a) : c
    }

    function w(c, a) {
        return c >>>
            a | c << 32 - a
    }

    function t(c, a) {
        var k = null,
            k = new b(c.a, c.b);
        return k = 32 >= a ? new b(k.a >>> a | k.b << 32 - a & 4294967295, k.b >>> a | k.a << 32 - a & 4294967295) : new b(k.b >>> a - 32 | k.a << 64 - a & 4294967295, k.a >>> a - 32 | k.b << 64 - a & 4294967295)
    }

    function T(c, a) {
        var k = null;
        return k = 32 >= a ? new b(c.a >>> a, c.b >>> a | c.a << 32 - a & 4294967295) : new b(0, c.a >>> a - 32)
    }

    function aa(c, a, b) {
        return c & a ^ ~c & b
    }

    function ba(c, a, k) {
        return new b(c.a & a.a ^ ~c.a & k.a, c.b & a.b ^ ~c.b & k.b)
    }

    function U(c, a, b) {
        return c & a ^ c & b ^ a & b
    }

    function ca(c, a, k) {
        return new b(c.a & a.a ^ c.a & k.a ^ a.a &
            k.a, c.b & a.b ^ c.b & k.b ^ a.b & k.b)
    }

    function da(c) {
        return w(c, 2) ^ w(c, 13) ^ w(c, 22)
    }

    function ea(c) {
        var a = t(c, 28),
            k = t(c, 34);
        c = t(c, 39);
        return new b(a.a ^ k.a ^ c.a, a.b ^ k.b ^ c.b)
    }

    function fa(c) {
        return w(c, 6) ^ w(c, 11) ^ w(c, 25)
    }

    function ga(c) {
        var a = t(c, 14),
            k = t(c, 18);
        c = t(c, 41);
        return new b(a.a ^ k.a ^ c.a, a.b ^ k.b ^ c.b)
    }

    function ha(c) {
        return w(c, 7) ^ w(c, 18) ^ c >>> 3
    }

    function ia(c) {
        var a = t(c, 1),
            k = t(c, 8);
        c = T(c, 7);
        return new b(a.a ^ k.a ^ c.a, a.b ^ k.b ^ c.b)
    }

    function ja(c) {
        return w(c, 17) ^ w(c, 19) ^ c >>> 10
    }

    function ka(c) {
        var a = t(c, 19),
            k = t(c, 61);
        c = T(c, 6);
        return new b(a.a ^ k.a ^ c.a, a.b ^ k.b ^ c.b)
    }

    function G(c, a) {
        var b = (c & 65535) + (a & 65535);
        return ((c >>> 16) + (a >>> 16) + (b >>> 16) & 65535) << 16 | b & 65535
    }

    function la(c, a, b, e) {
        var h = (c & 65535) + (a & 65535) + (b & 65535) + (e & 65535);
        return ((c >>> 16) + (a >>> 16) + (b >>> 16) + (e >>> 16) + (h >>> 16) & 65535) << 16 | h & 65535
    }

    function H(c, a, b, e, h) {
        var d = (c & 65535) + (a & 65535) + (b & 65535) + (e & 65535) + (h & 65535);
        return ((c >>> 16) + (a >>> 16) + (b >>> 16) + (e >>> 16) + (h >>> 16) + (d >>> 16) & 65535) << 16 | d & 65535
    }

    function ma(c, a) {
        var d, e, h;
        d = (c.b & 65535) + (a.b & 65535);
        e = (c.b >>> 16) +
            (a.b >>> 16) + (d >>> 16);
        h = (e & 65535) << 16 | d & 65535;
        d = (c.a & 65535) + (a.a & 65535) + (e >>> 16);
        e = (c.a >>> 16) + (a.a >>> 16) + (d >>> 16);
        return new b((e & 65535) << 16 | d & 65535, h)
    }

    function na(c, a, d, e) {
        var h, n, g;
        h = (c.b & 65535) + (a.b & 65535) + (d.b & 65535) + (e.b & 65535);
        n = (c.b >>> 16) + (a.b >>> 16) + (d.b >>> 16) + (e.b >>> 16) + (h >>> 16);
        g = (n & 65535) << 16 | h & 65535;
        h = (c.a & 65535) + (a.a & 65535) + (d.a & 65535) + (e.a & 65535) + (n >>> 16);
        n = (c.a >>> 16) + (a.a >>> 16) + (d.a >>> 16) + (e.a >>> 16) + (h >>> 16);
        return new b((n & 65535) << 16 | h & 65535, g)
    }

    function oa(c, a, d, e, h) {
        var n, g, l;
        n = (c.b &
            65535) + (a.b & 65535) + (d.b & 65535) + (e.b & 65535) + (h.b & 65535);
        g = (c.b >>> 16) + (a.b >>> 16) + (d.b >>> 16) + (e.b >>> 16) + (h.b >>> 16) + (n >>> 16);
        l = (g & 65535) << 16 | n & 65535;
        n = (c.a & 65535) + (a.a & 65535) + (d.a & 65535) + (e.a & 65535) + (h.a & 65535) + (g >>> 16);
        g = (c.a >>> 16) + (a.a >>> 16) + (d.a >>> 16) + (e.a >>> 16) + (h.a >>> 16) + (n >>> 16);
        return new b((g & 65535) << 16 | n & 65535, l)
    }

    function B(c, a) {
        return new b(c.a ^ a.a, c.b ^ a.b)
    }

    function A(c) {
        var a = [],
            d;
        if ("SHA-1" === c) a = [1732584193, 4023233417, 2562383102, 271733878, 3285377520];
        else if (0 === c.lastIndexOf("SHA-", 0)) switch (a = [3238371032, 914150663, 812702999, 4144912697, 4290775857, 1750603025, 1694076839, 3204075428], d = [1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225], c) {
            case "SHA-224":
                break;
            case "SHA-256":
                a = d;
                break;
            case "SHA-384":
                a = [new b(3418070365, a[0]), new b(1654270250, a[1]), new b(2438529370, a[2]), new b(355462360, a[3]), new b(1731405415, a[4]), new b(41048885895, a[5]), new b(3675008525, a[6]), new b(1203062813, a[7])];
                break;
            case "SHA-512":
                a = [new b(d[0], 4089235720), new b(d[1], 2227873595),
                new b(d[2], 4271175723), new b(d[3], 1595750129), new b(d[4], 2917565137), new b(d[5], 725511199), new b(d[6], 4215389547), new b(d[7], 327033209)
                ];
                break;
            default:
                throw Error("Unknown SHA variant");
        } else if (0 === c.lastIndexOf("SHA3-", 0) || 0 === c.lastIndexOf("SHAKE", 0))
            for (c = 0; 5 > c; c += 1) a[c] = [new b(0, 0), new b(0, 0), new b(0, 0), new b(0, 0), new b(0, 0)];
        else throw Error("No SHA variants supported");
        return a
    }

    function K(c, a) {
        var b = [],
            e, d, n, g, l, p, f;
        e = a[0];
        d = a[1];
        n = a[2];
        g = a[3];
        l = a[4];
        for (f = 0; 80 > f; f += 1) b[f] = 16 > f ? c[f] : y(b[f -
            3] ^ b[f - 8] ^ b[f - 14] ^ b[f - 16], 1), p = 20 > f ? H(y(e, 5), d & n ^ ~d & g, l, 1518500249, b[f]) : 40 > f ? H(y(e, 5), d ^ n ^ g, l, 1859775393, b[f]) : 60 > f ? H(y(e, 5), U(d, n, g), l, 2400959708, b[f]) : H(y(e, 5), d ^ n ^ g, l, 3395469782, b[f]), l = g, g = n, n = y(d, 30), d = e, e = p;
        a[0] = G(e, a[0]);
        a[1] = G(d, a[1]);
        a[2] = G(n, a[2]);
        a[3] = G(g, a[3]);
        a[4] = G(l, a[4]);
        return a
    }

    function Z(c, a, b, e) {
        var d;
        for (d = (a + 65 >>> 9 << 4) + 15; c.length <= d;) c.push(0);
        c[a >>> 5] |= 128 << 24 - a % 32;
        a += b;
        c[d] = a & 4294967295;
        c[d - 1] = a / 4294967296 | 0;
        a = c.length;
        for (d = 0; d < a; d += 16) e = K(c.slice(d, d + 16), e);
        return e
    }

    function L(c,
        a, k) {
        var e, h, n, g, l, p, f, m, q, u, r, t, v, w, y, A, z, x, F, B, C, D, E = [],
            J;
        if ("SHA-224" === k || "SHA-256" === k) u = 64, t = 1, D = Number, v = G, w = la, y = H, A = ha, z = ja, x = da, F = fa, C = U, B = aa, J = d;
        else if ("SHA-384" === k || "SHA-512" === k) u = 80, t = 2, D = b, v = ma, w = na, y = oa, A = ia, z = ka, x = ea, F = ga, C = ca, B = ba, J = V;
        else throw Error("Unexpected error in SHA-2 implementation");
        k = a[0];
        e = a[1];
        h = a[2];
        n = a[3];
        g = a[4];
        l = a[5];
        p = a[6];
        f = a[7];
        for (r = 0; r < u; r += 1) 16 > r ? (q = r * t, m = c.length <= q ? 0 : c[q], q = c.length <= q + 1 ? 0 : c[q + 1], E[r] = new D(m, q)) : E[r] = w(z(E[r - 2]), E[r - 7], A(E[r - 15]), E[r -
            16]), m = y(f, F(g), B(g, l, p), J[r], E[r]), q = v(x(k), C(k, e, h)), f = p, p = l, l = g, g = v(n, m), n = h, h = e, e = k, k = v(m, q);
        a[0] = v(k, a[0]);
        a[1] = v(e, a[1]);
        a[2] = v(h, a[2]);
        a[3] = v(n, a[3]);
        a[4] = v(g, a[4]);
        a[5] = v(l, a[5]);
        a[6] = v(p, a[6]);
        a[7] = v(f, a[7]);
        return a
    }

    function D(c, a) {
        var d, e, h, n, g = [],
            l = [];
        if (null !== c)
            for (e = 0; e < c.length; e += 2) a[(e >>> 1) % 5][(e >>> 1) / 5 | 0] = B(a[(e >>> 1) % 5][(e >>> 1) / 5 | 0], new b(c[e + 1], c[e]));
        for (d = 0; 24 > d; d += 1) {
            n = A("SHA3-");
            for (e = 0; 5 > e; e += 1) {
                h = a[e][0];
                var p = a[e][1],
                    f = a[e][2],
                    m = a[e][3],
                    q = a[e][4];
                g[e] = new b(h.a ^ p.a ^ f.a ^
                    m.a ^ q.a, h.b ^ p.b ^ f.b ^ m.b ^ q.b)
            }
            for (e = 0; 5 > e; e += 1) l[e] = B(g[(e + 4) % 5], S(g[(e + 1) % 5], 1));
            for (e = 0; 5 > e; e += 1)
                for (h = 0; 5 > h; h += 1) a[e][h] = B(a[e][h], l[e]);
            for (e = 0; 5 > e; e += 1)
                for (h = 0; 5 > h; h += 1) n[h][(2 * e + 3 * h) % 5] = S(a[e][h], W[e][h]);
            for (e = 0; 5 > e; e += 1)
                for (h = 0; 5 > h; h += 1) a[e][h] = B(n[e][h], new b(~n[(e + 1) % 5][h].a & n[(e + 2) % 5][h].a, ~n[(e + 1) % 5][h].b & n[(e + 2) % 5][h].b));
            a[0][0] = B(a[0][0], X[d])
        }
        return a
    }
    var d, V, W, X;
    d = [1116352408, 1899447441, 3049323471, 3921009573, 961987163, 1508970993, 2453635748, 2870763221, 3624381080, 310598401, 607225278,
        1426881987, 1925078388, 2162078206, 2614888103, 3248222580, 3835390401, 4022224774, 264347078, 604807628, 770255983, 1249150122, 1555081692, 1996064986, 2554220882, 2821834349, 2952996808, 3210313671, 3336571891, 3584528711, 113926993, 338241895, 666307205, 773529912, 1294757372, 1396182291, 1695183700, 1986661051, 2177026350, 2456956037, 2730485921, 2820302411, 3259730800, 3345764771, 3516065817, 3600352804, 4094571909, 275423344, 430227734, 506948616, 659060556, 883997877, 958139571, 1322822218, 1537002063, 1747873779, 1955562222, 2024104815,
        2227730452, 2361852424, 2428436474, 2756734187, 3204031479, 3329325298
    ];
    V = [new b(d[0], 3609767458), new b(d[1], 602891725), new b(d[2], 3964484399), new b(d[3], 2173295548), new b(d[4], 4081628472), new b(d[5], 3053834265), new b(d[6], 2937671579), new b(d[7], 3664609560), new b(d[8], 2734883394), new b(d[9], 1164996542), new b(d[10], 1323610764), new b(d[11], 3590304994), new b(d[12], 4068182383), new b(d[13], 991336113), new b(d[14], 633803317), new b(d[15], 3479774868), new b(d[16], 2666613458), new b(d[17], 944711139), new b(d[18], 2341262773),
    new b(d[19], 2007800933), new b(d[20], 1495990901), new b(d[21], 1856431235), new b(d[22], 3175218132), new b(d[23], 2198950837), new b(d[24], 3999719339), new b(d[25], 766784016), new b(d[26], 2566594879), new b(d[27], 3203337956), new b(d[28], 1034457026), new b(d[29], 2466948901), new b(d[30], 3758326383), new b(d[31], 168717936), new b(d[32], 1188179964), new b(d[33], 1546045734), new b(d[34], 1522805485), new b(d[35], 2643833823), new b(d[36], 2343527390), new b(d[37], 1014477480), new b(d[38], 1206759142), new b(d[39], 344077627),
    new b(d[40], 1290863460), new b(d[41], 3158454273), new b(d[42], 3505952657), new b(d[43], 106217008), new b(d[44], 3606008344), new b(d[45], 1432725776), new b(d[46], 1467031594), new b(d[47], 851169720), new b(d[48], 3100823752), new b(d[49], 1363258195), new b(d[50], 3750685593), new b(d[51], 3785050280), new b(d[52], 3318307427), new b(d[53], 3812723403), new b(d[54], 2003034995), new b(d[55], 3602036899), new b(d[56], 1575990012), new b(d[57], 1125592928), new b(d[58], 2716904306), new b(d[59], 442776044), new b(d[60], 593698344), new b(d[61],
        3733110249), new b(d[62], 2999351573), new b(d[63], 3815920427), new b(3391569614, 3928383900), new b(3515267271, 566280711), new b(3940187606, 3454069534), new b(4118630271, 4000239992), new b(116418474, 1914138554), new b(174292421, 2731055270), new b(289380356, 3203993006), new b(460393269, 320620315), new b(685471733, 587496836), new b(852142971, 1086792851), new b(1017036298, 365543100), new b(1126000580, 2618297676), new b(1288033470, 3409855158), new b(1501505948, 4234509866), new b(1607167915, 987167468), new b(1816402316,
            1246189591)
    ];
    X = [new b(0, 1), new b(0, 32898), new b(2147483648, 32906), new b(2147483648, 2147516416), new b(0, 32907), new b(0, 2147483649), new b(2147483648, 2147516545), new b(2147483648, 32777), new b(0, 138), new b(0, 136), new b(0, 2147516425), new b(0, 2147483658), new b(0, 2147516555), new b(2147483648, 139), new b(2147483648, 32905), new b(2147483648, 32771), new b(2147483648, 32770), new b(2147483648, 128), new b(0, 32778), new b(2147483648, 2147483658), new b(2147483648, 2147516545), new b(2147483648, 32896), new b(0, 2147483649),
    new b(2147483648, 2147516424)
    ];
    W = [
        [0, 36, 3, 41, 18],
        [1, 44, 10, 45, 2],
        [62, 6, 43, 15, 61],
        [28, 55, 25, 21, 56],
        [27, 20, 39, 8, 14]
    ];
    "function" === typeof define && define.amd ? define(function () {
        return C
    }) : "undefined" !== typeof exports ? ("undefined" !== typeof module && module.exports && (module.exports = C), exports = C) : Y.jsSHA = C
})(this);



/*
优化说明
    1、改成中文 "确定"、"取消" 按钮。
    2、select 新增了 textContents 数组。
    3、新增了skin: 'tab'换页切换菜单样式
    4、更新部分翻译
    5、优化字体显示效果
    6、优化同一行内CSS样式
*/


// The GM_config constructor
function GM_configStruct() {
    // call init() if settings were passed to constructor
    if (arguments.length) {
        GM_configInit(this, arguments);
        this.onInit();
    }
}

// This is the initializer function
function GM_configInit(config, args) {
    // Initialize instance variables
    if (typeof config.fields == "undefined") {
        config.fields = {};
        config.onInit = config.onInit || function () { };
        config.onOpen = config.onOpen || function () { };
        config.onSave = config.onSave || function () { };
        config.onClose = config.onClose || function () { };
        config.onReset = config.onReset || function () { };
        config.isOpen = false;
        config.title = '用户脚本设置';
        config.css = {
            basic: [
                "#GM_config * { font-family: arial,tahoma,myriad pro,sans-serif; }",
                "#GM_config { background: #FFF; }",
                "#GM_config input[type='radio'] { margin-right: 8px; }",
                "#GM_config .indent40 { margin-left: 40%; }",
                "#GM_config .field_label { font-size: 14px; font-weight: bold; margin-right: 6px; }",
                "#GM_config .radio_label { font-size: 14px; }",
                "#GM_config .block { display: block; }",
                "#GM_config .saveclose_buttons { margin: 16px 10px 10px; padding: 2px 12px; }",
                "#GM_config .reset, #GM_config .reset a," +
                " #GM_config_buttons_holder { color: #000; text-align: right; }",
                "#GM_config .config_header { font-size: 20pt; margin: 0; }",
                "#GM_config .config_desc, #GM_config .section_desc, #GM_config .reset { font-size: 9pt; }",
                "#GM_config .center { text-align: center; }",
                "#GM_config .section_header_holder { margin-top: 8px; }",
                "#GM_config .config_var { margin: 0 0 4px; }",
                "#GM_config .section_header { background: #414141; border: 1px solid #000; color: #FFF;" +
                " font-size: 12pt; margin: 0; }",
                "#GM_config .section_desc { background: #EFEFEF; border: 1px solid #CCC; color: #575757;" +
                " font-size: 10pt; margin: 0 0 6px; }",
                // newer
                "#GM_config input[type='number'] { width: 60px; }",
                "#GM_config .nav-tabs { margin: 10 0}",
                "#GM_config .nav-tabs > div { display: inline; padding: 3px 10px; }",
                "#pv-prefs .section_header_holder { padding-left: 10px; }",
            ].join('\n') + '\n',
            skin_tab: [
                "#GM_config { background: #EEE; }",
                "#GM_config textarea { width: 98%; height: 45px; margin-top: 5px; }",
                "#GM_config .field_label { display: inline-block; font-weight: normal; }",
                // 在同一行内的设置
                "#GM_config .inline input[type='checkbox'] {margin: 3px 3px 3px 0px;}",
                "#GM_config .inline .config_var { margin-left: 15px; }",
                // 内容样式
                "#GM_config .config_var { font-size: 14px; padding: 5px; margin: 0; }",
                "#GM_config .config_header a { text-decoration: none; color: #000; }",
                "#GM_config .nav-tabs { margin: 20 0}",
                "#GM_config .nav-tabs > div { font-size: 15px; color: #999; cursor: pointer; padding: 10px 20px; }",
                "#GM_config .nav-tabs > .active { cursor: default; color: #FFF; }",
                "#GM_config .nav-tabs > div:hover { color: #FFF; }",
            ].join('\n') + '\n',
            skin_1: [ // 仿 Mouseover Popup Image Viewer 样式
                "#GM_config { background: #EEE; }",
                "#GM_config textarea { width: 98%; height: 45px; margin-top: 5px; }",
                "#GM_config .config_var { font-size: 12px; }",
                "#GM_config .inline .config_var { margin-left: 15px; }",
                "#GM_config .field_label { display: inline-block; font-weight: normal; }",
                "#GM_config { padding: 20px 30px; margin: 0; }",
                "#GM_config .config_header { margin-bottom: 10px; }",
                "#GM_config div.config_var { padding: 7px 0; }",
            ].join('\n') + '\n',
            basicPrefix: "GM_config",
            stylish: ""
        };
    }

    if (args.length == 1 &&
        typeof args[0].id == "string" &&
        typeof args[0].appendChild != "function") var settings = args[0];
    else {
        // Provide backwards-compatibility with argument style intialization
        var settings = {};

        // loop through GM_config.init() arguments
        for (var i = 0, l = args.length, arg; i < l; ++i) {
            arg = args[i];

            // An element to use as the config window
            if (typeof arg.appendChild == "function") {
                settings.frame = arg;
                continue;
            }

            switch (typeof arg) {
                case 'object':
                    for (var j in arg) { // could be a callback functions or settings object
                        if (typeof arg[j] != "function") { // we are in the settings object
                            if (typeof arg[j] == 'string') {
                                settings.frameStyle = arg;
                            } else {
                                settings.fields = arg; // store settings object
                            }
                            break; // leave the loop
                        } // otherwise it must be a callback function
                        if (!settings.events) settings.events = {};
                        settings.events[j] = arg[j];
                    }
                    break;
                case 'function': // passing a bare function is set to open callback
                    settings.events = {
                        open: arg
                    };
                    break;
                case 'string': // could be custom CSS or the title string
                    // if (/[\w\.]+\s*\{\s*[\w-]+\s*:\s*\w+[\s|\S]*\}/.test(arg))
                    if (/[\w\.]+\s*\{\s*[\w-]+\s*:[\s|\S]*\}/.test(arg))
                        settings.css = arg;
                    else if (arg)
                        settings.title = arg;
                    break;
            }
        }
    }

    /* Initialize everything using the new settings object */
    // Set the id
    if (settings.id) config.id = settings.id;
    else if (typeof config.id == "undefined") config.id = 'GM_config';

    // Set the title
    if (settings.title) config.title = settings.title;

    // Set the custom css
    if (settings.css) config.css.stylish = settings.css;

    if (settings.skin) {
        var skin = config.css['skin_' + settings.skin];
        if (skin) {
            config.css.basic += skin;
        }
    }

    // Set the frame
    if (settings.frame) config.frame = settings.frame;
    if (settings.frameStyle) config.frameStyle = settings.frameStyle;

    config.isTabs = settings.isTabs;

    // Set the event callbacks
    if (settings.events) {
        var events = settings.events;
        for (var e in events)
            config["on" + e.charAt(0).toUpperCase() + e.slice(1)] = events[e];
    }

    // Create the fields
    if (settings.fields) {
        var stored = config.read(), // read the stored settings
            fields = settings.fields,
            customTypes = settings.types || {};

        for (var id in fields) {
            var field = fields[id];

            // for each field definition create a field object
            if (field)
                config.fields[id] = new GM_configField(field, stored[id], id,
                    customTypes[field.type]);
            else if (config.fields[id]) delete config.fields[id];
        }
    }

    // If the id has changed we must modify the default style
    if (config.id != config.css.basicPrefix) {
        config.css.basic = config.css.basic.replace(
            new RegExp('#' + config.css.basicPrefix, 'gm'), '#' + config.id);
        config.css.basicPrefix = config.id;
    }
}

GM_configStruct.prototype = {
    // Support old method of initalizing
    init: function () {
        GM_configInit(this, arguments);
        this.onInit();
    },

    // call GM_config.open() from your script to open the menu
    open: function () {
        // Die if the menu is already open on this page
        // You can have multiple instances but you can't open the same instance twice
        var match = document.getElementById(this.id);
        if (match && (match.tagName == "IFRAME" || match.childNodes.length > 0)) return;

        // Sometimes "this" gets overwritten so create an alias
        var config = this;

        // Function to build the mighty config window :)
        function buildConfigWin(body, head) {
            var create = config.create,
                fields = config.fields,
                configId = config.id,
                bodyWrapper = create('div', {
                    id: configId + '_wrapper'
                });

            // Append the style which is our default style plus the user style
            head.appendChild(
                create('style', {
                    type: 'text/css',
                    textContent: config.css.basic + config.css.stylish
                }));

            // Add header and title
            bodyWrapper.appendChild(create('div', {
                id: configId + '_header',
                className: 'config_header block center'
            }, config.title));

            // Append elements
            var section = bodyWrapper,
                secNum = 0; // Section count
            var lastParentNode = null;

            // loop through fields
            for (var id in fields) {
                var field = fields[id],
                    settings = field.settings;

                if (settings.section) { // the start of a new section
                    section = bodyWrapper.appendChild(create('div', {
                        className: 'section_header_holder',
                        id: configId + '_section_' + secNum
                    }));

                    if (Object.prototype.toString.call(settings.section) !== '[object Array]')
                        settings.section = [settings.section];

                    if (settings.section[0])
                        section.appendChild(create('div', {
                            className: 'section_header center',
                            id: configId + '_section_header_' + secNum
                        }, settings.section[0]));

                    if (settings.section[1])
                        section.appendChild(create('p', {
                            className: 'section_desc center',
                            id: configId + '_section_desc_' + secNum
                        }, settings.section[1]));
                    ++secNum;
                }

                if (settings.line == 'start' && lastParentNode) { // 切换到下一行
                    lastParentNode = null;
                }

                // Create field elements and append to current section
                (lastParentNode || section).appendChild((field.wrapper = field.toNode(configId, lastParentNode)));

                if (settings.line == 'start') {
                    lastParentNode = field.wrapper;
                    lastParentNode.classList.add('inline')
                } else if (settings.line == 'end') {
                    lastParentNode = null;
                }
            }

            // Add save and close buttons
            bodyWrapper.appendChild(create('div', {
                id: configId + '_buttons_holder'
            },

                create('button', {
                    id: configId + '_saveBtn',
                    textContent: '确定',
                    title: '部分选项需要刷新页面才能生效',
                    className: 'saveclose_buttons',
                    onclick: function () {
                        config.save();
                        config.close();
                    }
                }),

                create('button', {
                    id: configId + '_closeBtn',
                    textContent: '取消',
                    title: '取消本次设置，所有选项还原',
                    className: 'saveclose_buttons',
                    onclick: function () {
                        config.close()
                    }
                }),

                create('div', {
                    className: 'reset_holder block'
                },

                    // Reset link
                    create('a', {
                        id: configId + '_resetLink',
                        textContent: '恢复默认设置',
                        href: '#',
                        title: '恢复所有设置的内容为默认值',
                        className: 'reset',
                        onclick: function (e) {
                            e.preventDefault();
                            config.reset()
                        }
                    })
                )));

            body.appendChild(bodyWrapper); // Paint everything to window at once
            config.center(); // Show and center iframe
            window.addEventListener('resize', config.center, false); // Center frame on resize

            // Call the open() callback function
            config.onOpen(config.frame.contentDocument || config.frame.ownerDocument,
                config.frame.contentWindow || window,
                config.frame);

            if (config.isTabs) {
                config.toTabs();
            }

            // Close frame on window close
            window.addEventListener('beforeunload', function () {
                config.close();
            }, false);

            // Now that everything is loaded, make it visible
            config.frame.style.display = "block";
            config.isOpen = true;
        }

        // Change this in the onOpen callback using this.frame.setAttribute('style', '')
        var defaultStyle = 'bottom: auto; border: 1px solid #000; display: none; height: 75%;' +
            ' left: 0; margin: 0; max-height: 95%; max-width: 95%; opacity: 0;' +
            ' overflow: auto; padding: 0; position: fixed; right: auto; top: 0;' +
            ' width: 75%; z-index: 999999999;';

        // Either use the element passed to init() or create an iframe
        if (this.frame) {
            this.frame.id = this.id; // Allows for prefixing styles with the config id
            this.frame.setAttribute('style', defaultStyle);
            buildConfigWin(this.frame, this.frame.ownerDocument.getElementsByTagName('head')[0]);
        } else {
            // Create frame
            document.body.appendChild((this.frame = this.create('iframe', {
                id: this.id,
                style: defaultStyle
            })));

            if (this.frameStyle) {
                Object.keys(this.frameStyle).forEach(function (key) {
                    config.frame.style[key] = config.frameStyle[key];
                })
            }

            // In WebKit src can't be set until it is added to the page
            this.frame.src = 'about:blank';
            // we wait for the iframe to load before we can modify it
            this.frame.addEventListener('load', function (e) {
                var frame = config.frame;
                var body = frame.contentDocument.getElementsByTagName('body')[0];
                body.id = config.id; // Allows for prefixing styles with the config id
                buildConfigWin(body, frame.contentDocument.getElementsByTagName('head')[0]);
            }, false);
        }
    },

    save: function () {
        var forgotten = this.write();
        this.onSave(forgotten); // Call the save() callback function
    },

    close: function () {
        if (!this.frame) return;
        // If frame is an iframe then remove it
        if (this.frame.contentDocument) {
            this.remove(this.frame);
            this.frame = null;
        } else { // else wipe its content
            this.frame.innerHTML = "";
            this.frame.style.display = "none";
        }

        // Null out all the fields so we don't leak memory
        var fields = this.fields;
        for (var id in fields) {
            var field = fields[id];
            field.wrapper = null;
            field.node = null;
        }

        this.onClose(); //  Call the close() callback function
        this.isOpen = false;
    },

    set: function (name, val) {
        this.fields[name].value = val;

        if (this.fields[name].node) {
            this.fields[name].reload();
        }
    },

    get: function (name, getLive) {
        var field = this.fields[name],
            fieldVal = null;

        if (getLive && field.node) {
            fieldVal = field.toValue();
        }

        return fieldVal != null ? fieldVal : field.value;
    },

    write: function (store, obj) {
        if (!obj) {
            var values = {},
                forgotten = {},
                fields = this.fields;

            for (var id in fields) {
                var field = fields[id];
                var value = field.toValue();

                if (field.save) {
                    if (value != null) {
                        values[id] = value;
                        field.value = value;
                    } else
                        values[id] = field.value;
                } else
                    forgotten[id] = value;
            }
        }
        try {
            this.setValue(store || this.id, this.stringify(obj || values));
        } catch (e) {
            this.log("GM_config failed to save settings!");
        }

        return forgotten;
    },

    read: function (store) {
        try {
            var rval = this.parser(this.getValue(store || this.id, '{}'));
        } catch (e) {
            this.log("GM_config failed to read saved settings!");
            var rval = {};
        }
        return rval;
    },

    reset: function () {
        var fields = this.fields;

        // Reset all the fields
        for (var id in fields) fields[id].reset();

        this.onReset(); // Call the reset() callback function
    },

    create: function () {
        switch (arguments.length) {
            case 1:
                var A = document.createTextNode(arguments[0]);
                break;
            default:
                var A = document.createElement(arguments[0]),
                    B = arguments[1];
                for (var b in B) {
                    if (b.indexOf("on") == 0)
                        A.addEventListener(b.substring(2), B[b], false);
                    else if (",style,accesskey,id,name,src,href,which,for".indexOf("," +
                        b.toLowerCase()) != -1)
                        A.setAttribute(b, B[b]);
                    else if (typeof B[b] != 'undefined')
                        A[b] = B[b];
                }
                if (typeof arguments[2] == "string")
                    A.innerHTML = arguments[2];
                else
                    for (var i = 2, len = arguments.length; i < len; ++i)
                        A.appendChild(arguments[i]);
        }
        return A;
    },

    center: function () {
        var node = this.frame;
        if (!node) return;
        var style = node.style,
            beforeOpacity = style.opacity;
        if (style.display == 'none') style.opacity = '0';
        style.display = '';
        style.top = Math.floor((window.innerHeight / 2) - (node.offsetHeight / 2)) + 'px';
        style.left = Math.floor((window.innerWidth / 2) - (node.offsetWidth / 2)) + 'px';
        style.opacity = '1';
    },

    remove: function (el) {
        if (el && el.parentNode) el.parentNode.removeChild(el);
    },

    toTabs: function () { // 转为 tab 的形式
        var body = this.frame.tagName == 'IFRAME' ? this.frame.contentWindow.document : this.frame,
            configId = this.id;
        var $ = function (id) {
            return body.getElementById(configId + '_' + id);
        };

        var headers = body.querySelectorAll('.section_header');
        if (!headers.length) return;

        var anch = this.create('div', {
            // id: configId + '_tab_holder',
            className: 'nav-tabs',
        });

        for (var i = 0, header; i < headers.length; i++) {
            header = headers[i];
            if (i == 0) {
                header.classList.add('active');
            }
            anch.appendChild(header);
        }

        anch.addEventListener('click', this.toggleTab.bind(this), false);

        $('section_0').parentNode.insertBefore(anch, $('section_0'));

        var curTab = localStorage.getItem('picviewerCE.config.curTab') || 0;
        this.toggleTab(parseInt(curTab, 10));
    },
    toggleTab: function (e) {
        var body = this.frame.tagName == 'IFRAME' ? this.frame.contentWindow.document : this.frame,
            configId = this.id;

        var curTab = typeof e == 'number' ? e : /\_(\d+)/.exec(e.target.id)[1];

        [].forEach.call(body.querySelectorAll('.section_header'), function (header, i) {
            if (i == curTab) {
                header.classList.add('active');
            } else {
                header.classList.remove('active');
            }
        });

        [].forEach.call(body.querySelectorAll('.section_header_holder'), function (holder, i) {
            holder.style.display = (i == curTab) ? 'block' : 'none';
        });

        localStorage.setItem('picviewerCE.config.curTab', curTab)
    }
};

// Define a bunch of API stuff
(function () {
    var isGM = typeof GM_getValue != 'undefined' &&
        typeof GM_getValue('a', 'b') != 'undefined',
        setValue, getValue, stringify, parser;

    // Define value storing and reading API
    if (!isGM) {
        setValue = function (name, value) {
            return localStorage.setItem(name, value);
        };
        getValue = function (name, def) {
            var s = localStorage.getItem(name);
            return s == null ? def : s
        };

        // We only support JSON parser outside GM
        stringify = JSON.stringify;
        parser = JSON.parse;
    } else {
        setValue = GM_setValue;
        getValue = GM_getValue;
        stringify = typeof JSON == "undefined" ?
            function (obj) {
                return obj.toSource();
            } : JSON.stringify;
        parser = typeof JSON == "undefined" ?
            function (jsonData) {
                return (new Function('return ' + jsonData + ';'))();
            } : JSON.parse;
    }

    GM_configStruct.prototype.isGM = isGM;
    GM_configStruct.prototype.setValue = setValue;
    GM_configStruct.prototype.getValue = getValue;
    GM_configStruct.prototype.stringify = stringify;
    GM_configStruct.prototype.parser = parser;
    GM_configStruct.prototype.log = window.console ?
        console.log : (isGM && typeof GM_log != 'undefined' ?
            GM_log : (window.opera ?
                opera.postError : function () {
                    /* no logging */
                }
            ));
})();

function GM_configDefaultValue(type, options) {
    var value;

    if (type && type.indexOf('unsigned ') == 0)
        type = type.substring(9);

    switch (type) {
        case 'radio':
        case 'select':
            value = options[0];
            break;
        case 'checkbox':
            value = false;
            break;
        case 'int':
        case 'integer':
        case 'float':
        case 'number':
            value = 0;
            break;
        default:
            value = '';
    }

    return value;
}

function GM_configField(settings, stored, id, customType) {
    // Store the field's settings
    this.settings = settings;
    this.id = id;
    this.node = null;
    this.wrapper = null;
    this.save = typeof settings.save == "undefined" ? true : settings.save;

    // Buttons are static and don't have a stored value
    if (settings.type == "button") this.save = false;
    if (settings.type == "span") this.save = false;

    // if a default value wasn't passed through init() then
    //   if the type is custom use its default value
    //   else use default value for type
    // else use the default value passed through init()
    this['default'] = typeof settings['default'] == "undefined" ?
        customType ?
            customType['default'] :
            GM_configDefaultValue(settings.type, settings.options) :
        settings['default'];

    // Store the field's value
    this.value = typeof stored == "undefined" ? this['default'] : stored;

    // Setup methods for a custom type
    if (customType) {
        this.toNode = customType.toNode;
        this.toValue = customType.toValue;
        this.reset = customType.reset;
    }
}

GM_configField.prototype = {
    create: GM_configStruct.prototype.create,

    toNode: function (configId, lastParentNode) {
        var field = this.settings,
            value = this.value,
            options = field.options,
            type = field.type,
            id = this.id,
            labelPos = field.labelPos,
            create = this.create;

        function addLabel(pos, labelEl, parentNode, beforeEl) {
            if (!beforeEl) {
                beforeEl = lastParentNode ? parentNode.lastChild : parentNode.firstChild; // oneLine 的修正
            }

            switch (pos) {
                case 'right':
                case 'below':
                    if (pos == 'below')
                        parentNode.appendChild(create('br', {}));
                    parentNode.appendChild(labelEl);
                    break;
                default:
                    if (pos == 'above')
                        parentNode.insertBefore(create('br', {}), beforeEl);
                    parentNode.insertBefore(labelEl, beforeEl);
            }
        }

        var retNode = create('div', {
            className: 'config_var',
            id: configId + '_' + id + '_var',
            title: field.title || ''
        }),
            firstProp;

        // Retrieve the first prop
        for (var i in field) {
            firstProp = i;
            break;
        }

        var label = field.label && type != "button" ?
            create('label', {
                id: configId + '_' + id + '_field_label',
                for: configId + '_field_' + id,
                className: 'field_label'
            }, field.label) : null;

        switch (type) {
            case 'span':
                label = null;

                this.node = create('span', {
                    innerHTML: field.label,
                    className: 'field_label',
                    title: field.title,
                    style: field.style
                });
                retNode = this.node;
                break;
            case 'textarea':
                retNode.appendChild((this.node = create('textarea', {
                    innerHTML: value,
                    id: configId + '_field_' + id,
                    className: 'block' + (field.className ? (" " + field.className) : ''),
                    cols: (field.cols ? field.cols : 20),
                    rows: (field.rows ? field.rows : 2),
                    placeholder: field.placeholder
                })));
                break;
            case 'radio':
                var wrap = create('div', {
                    id: configId + '_field_' + id,
                    className: field.className
                });
                this.node = wrap;

                for (var i = 0, len = options.length; i < len; ++i) {
                    var radLabel = create('label', {
                        className: 'radio_label'
                    }, options[i]);

                    var rad = wrap.appendChild(create('input', {
                        value: options[i],
                        type: 'radio',
                        name: id,
                        checked: options[i] == value
                    }));

                    var radLabelPos = labelPos &&
                        (labelPos == 'left' || labelPos == 'right') ?
                        labelPos : firstProp == 'options' ? 'left' : 'right';

                    addLabel(radLabelPos, radLabel, wrap, rad);
                }

                retNode.appendChild(wrap);
                break;
            case 'select':
                var wrap = create('select', {
                    id: configId + '_field_' + id
                });
                this.node = wrap;

                for (var i = 0, len = options.length; i < len; ++i) {
                    var option = options[i];
                    wrap.appendChild(create('option', {
                        value: option,
                        selected: option == value
                    }, option));
                }

                retNode.appendChild(wrap);
                break;
            default: // fields using input elements
                var props = {
                    id: configId + '_field_' + id,
                    type: type,
                    value: type == 'button' ? field.label : value
                };

                switch (type) {
                    case 'checkbox':
                        props.checked = value;
                        break;
                    case 'button':
                        props.size = field.size ? field.size : 25;
                        if (field.script) field.click = field.script;
                        if (field.click) props.onclick = field.click;
                        break;
                    case 'hidden':
                        break;
                    default:
                        // type = text, int, or float
                        props.type = 'text';
                        props.size = field.size ? field.size : 25;
                }

                retNode.appendChild((this.node = create('input', props)));
        }

        if (label) {
            // If the label is passed first, insert it before the field
            // else insert it after
            if (!labelPos)
                labelPos = firstProp == "label" || type == "radio" ?
                    "left" : "right";

            addLabel(labelPos, label, retNode);
        }

        return retNode;
    },

    toValue: function () {
        var node = this.node,
            field = this.settings,
            type = field.type,
            unsigned = false,
            rval = null;

        if (!node) return rval;

        if (type.indexOf('unsigned ') == 0) {
            type = type.substring(9);
            unsigned = true;
        }

        switch (type) {
            case 'checkbox':
                rval = node.checked;
                break;
            case 'select':
                rval = node[node.selectedIndex].value;
                break;
            case 'radio':
                var radios = node.getElementsByTagName('input');
                for (var i = 0, len = radios.length; i < len; ++i)
                    if (radios[i].checked)
                        rval = radios[i].value;
                break;
            case 'button':
                break;
            case 'int':
            case 'integer':
            case 'float':
            case 'number':
                var num = Number(node.value);
                var warn = '输入字符 "' + field.label + '" 要求必须为' +
                    (unsigned ? ' 正 ' : 'n ') + '整数值';

                if (isNaN(num) || (type.substr(0, 3) == 'int' &&
                    Math.ceil(num) != Math.floor(num)) ||
                    (unsigned && num < 0)) {
                    alert(warn + '.');
                    return null;
                }

                if (!this._checkNumberRange(num, warn))
                    return null;
                rval = num;
                break;
            default:
                rval = node.value;
                break;
        }

        return rval; // value read successfully
    },

    reset: function () {
        var node = this.node,
            field = this.settings,
            type = field.type;

        if (!node) return;

        switch (type) {
            case 'checkbox':
                node.checked = this['default'];
                break;
            case 'select':
                for (var i = 0, len = node.options.length; i < len; ++i)
                    if (node.options[i].value == this['default'])
                        node.selectedIndex = i;
                break;
            case 'radio':
                var radios = node.getElementsByTagName('input');
                for (var i = 0, len = radios.length; i < len; ++i)
                    if (radios[i].value == this['default'])
                        radios[i].checked = true;
                break;
            case 'button':
                break;
            default:
                node.value = this['default'];
                break;
        }
    },

    remove: function (el) {
        GM_configStruct.prototype.remove(el || this.wrapper);
        this.wrapper = null;
        this.node = null;
    },

    reload: function () {
        var wrapper = this.wrapper;
        if (wrapper) {
            var fieldParent = wrapper.parentNode;
            fieldParent.insertBefore((this.wrapper = this.toNode()), wrapper);
            this.remove(wrapper);
        }
    },

    _checkNumberRange: function (num, warn) {
        var field = this.settings;
        if (typeof field.min == "number" && num < field.min) {
            alert(warn + ' greater than or equal to ' + field.min + '.');
            return null;
        }

        if (typeof field.max == "number" && num > field.max) {
            alert(warn + ' less than or equal to ' + field.max + '.');
            return null;
        }
        return true;
    }
};

// Create default instance of GM_config
var GM_config = new GM_configStruct();

/*waitForKeyElements*/
/*--- waitForKeyElements(): A utility function, for Greasemonkey scripts,
 that detects and handles AJAXed content.
  
 Usage example:
 waitForKeyElements ("div.comments", commentCallbackFunction);
  
 //--- Page-specific function to do what we want when the node is found.
 function commentCallbackFunction (jNode) {
     jNode.text ("This comment changed by waitForKeyElements().");
 }
  
 IMPORTANT: This function requires your script to have loaded jQuery.
 */

function waitForKeyElements(
    selectorTxt,
    /* Required: The jQuery selector string that
       specifies the desired element(s).
       */
    actionFunction,
    /* Required: The code to run when elements are
       found. It is passed a jNode to the matched
       element.
       */
    bWaitOnce,
    /* Optional: If false, will continue to scan for
       new elements even after the first match is
       found.
       */
    iframeSelector
    /* Optional: If set, identifies the iframe to
       search.
       */
) {
    var targetNodes, btargetsFound;

    if (typeof iframeSelector == "undefined")
        targetNodes = $(selectorTxt);
    else
        targetNodes = $(iframeSelector).contents()
            .find(selectorTxt);

    if (targetNodes && targetNodes.length > 0) {
        btargetsFound = true;
        /*--- Found target node(s). Go through each and act if they
        are new.
        */
        targetNodes.each(function () {
            var jThis = $(this);
            var alreadyFound = jThis.data('alreadyFound') || false;

            if (!alreadyFound) {
                //--- Call the payload function.
                var cancelFound = actionFunction(jThis);
                if (cancelFound)
                    btargetsFound = false;
                else
                    jThis.data('alreadyFound', true);
            }
        });
    } else {
        btargetsFound = false;
    }

    //--- Get the timer-control variable for this selector.
    var controlObj = waitForKeyElements.controlObj || {};
    var controlKey = selectorTxt.replace(/[^\w]/g, "_");
    var timeControl = controlObj[controlKey];

    //--- Now set or clear the timer as appropriate.
    if (btargetsFound && bWaitOnce && timeControl) {
        //--- The only condition where we need to clear the timer.
        clearInterval(timeControl);
        delete controlObj[controlKey];
    } else {
        //--- Set a timer, if needed.
        if (!timeControl) {
            timeControl = setInterval(function () {
                waitForKeyElements(selectorTxt,
                    actionFunction,
                    bWaitOnce,
                    iframeSelector
                );
            },
                300
            );
            controlObj[controlKey] = timeControl;
        }
    }
    waitForKeyElements.controlObj = controlObj;
}



(function () {
    'use strict';

    //版本信息
    const TIPS = {
        CurrentVersion: "143.2022.0816.1",
        LastUpdateDate: "2022.08.16",
        VersionTips: "115转存助手ui优化版 v3.7",
        UpdateUrl: "https://github.com/Nerver4Ever/SevenSha1UIAdvancedHelper",
        Sha1FileInputDetails: "",
    };

    const WORKSETTINGS = {
        WorkingItemsNumber: 3, //同时执行任务数
        SleepLittleTime: 1000, //短暂休眠,毫秒,暂时在转存中使用
        SleepMoreTime: 1000, //长时休眠,毫秒,暂时在提取中使用
        SleepMuchMoreTime: 8000, //超长休眠,暂时未使用
        ANumber: 27, //随机数,暂时未使用
    };

    GM_addStyle(`
    @keyframes hue {
        from {
            filter: hue-rotate(0);
        }
    
        to {
            filter: hue-rotate(360deg);
        }
    }
    
    .rainbow-text {
        display: inline-block;
        color: red;
        animation: hue 6s linear infinite;
        background-image: linear-gradient(to right bottom, rgb(255,0,0), rgb(255,255,0),rgb(255,0,255));
        -webkit-background-clip: text;
    }

        .my115Info{
            color:red
        }
        .btnInGrid{
            height:20px;
            width:20px;
            margin-left:-22px;
            margin-top:36px;
            border:0px;
            border-color:transparent;
            background-color:transparent;
        }

        .btnInGrid i{
            margin:3px -3px
        }

        li:hover .btnInGrid{
            background-color:#2777F8 !important
        }



        /* Style The Dropdown Button */
        .my115Dropbtn {
          background-color: #2777F8;
          color: white;
          font-size: 16px;
          border: none;
          cursor: pointer;
        }
        
        /* The container <div> - needed to position the dropdown content */
        .my115Dropdown {
          position: relative;
          display: inline-block;
        }
        
        /* Dropdown Content (Hidden by Default) */
        .my115Dropdown-content {
          display: none;
          position: absolute;
          background-color: #f9f9f9;
          min-width: 230px;
          box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
          z-index: 1;
          margin-top: 32px;
        }
        
        /* Links inside the dropdown */
        .my115Dropdown-content a {
          color: black;
          padding: 12px 16px;
          text-decoration: none;
          display: block;
          cursor: pointer;
          margin:4px;
        }
        
        /* Change color of dropdown links on hover */
        .my115Dropdown-content a:hover{
            background-color: #2777F8;
            color:white;
        }
        
        /* Show the dropdown menu on hover */
        .my115Dropdown:hover .my115Dropdown-content {
          display: block;
        }
        
        /* Change the background color of the dropdown button when the dropdown content is shown */
        .my115Dropdown:hover .my115Dropbtn {
          background-color: #3e8e41;
        }

    `);

    function getEnviromentInfo() {
        return `
       [gm]:${GM_info.scriptHandler}
       [gmVersion]:${GM_info.version}
       [ua]:${navigator.userAgent}
       [version]:${TIPS.CurrentVersion}
       `;
    }

    function config() {
        console.log("脚本与环境信息：（如果报bug，请附带上如下信息）")
        let env = getEnviromentInfo();
        console.log(env);



        var windowCss = '#Cfg4ne .nav-tabs {margin: 20 2} #Cfg4ne .config_var textarea{width: 310px; height: 50px;} #Cfg4ne .inline {padding-bottom:0px;} #Cfg4ne .config_header a:hover {color:#1e90ff;} #Cfg4ne .config_var {margin-left: 6%;margin-right: 6%;} #Cfg4ne input[type="checkbox"] {margin: 3px 3px 3px 0px;} #Cfg4ne input[type="text"] {width: 60px;} #Cfg4ne {background-color: lightgray;} #Cfg4ne .reset_holder {float: left; position: relative; bottom: -1em;} #Cfg4ne .saveclose_buttons {margin: .7em;} #Cfg4ne .section_desc {font-size: 10pt;}';

        GM_registerMenuCommand('设置', opencfg);

        function opencfg() {
            GM_config.open();
        };

        GM_config.init({
            id: 'Cfg4ne',
            title: GM_config.create('a', {
                href: TIPS.UpdateUrl,
                target: '_blank',
                className: 'setTitle',
                textContent: `${TIPS.VersionTips}设置`,
                title: `作者：Never4Ever 版本：${TIPS.CurrentVersion}点击访问主页`
            }),
            isTabs: true,
            skin: 'tab',
            css: windowCss,
            frameStyle: {
                height: '490px',
                width: '750px',
                zIndex: '2147483648',
            },
            fields: {
                createRootFolderDefaultValue: {
                    section: ['', '转存助手一些功能设置,发包参数暂未开放，敬请期待！'],
                    label: '“sha1转存时，强制在保存处新建根目录”这项默认选中',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: true,
                },

                createChildFolderVisible: {
                    label: '显示“sha1转存时，不创建任何子目录”选项；不显示则强制创建子目录',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: false,
                },
                createItemSha1: {
                    label: '列表模式下：悬浮条显示”获取sha1链接“',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: true,
                },
                createItemSha1InThumb: {
                    label: '缩略图模式下：显示”获取sha1链接“',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: true,
                },
                advancedRename: {
                    label: '在目录的悬浮工具条处显示“遍历文件夹”选项',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: false,
                },
                autoUseSeparator: {
                    label: '自动给文件名添加分隔符进行上传，以防文件名违规',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: true,
                },
                autoUseSeparatorToRename: {
                    label: '上传结束,自动给文件名去除分隔符，还原原文件名',
                    labelPos: 'right',
                    type: 'checkbox',
                    default: true,
                },
                separator: {
                    label: '分隔符方案(使用生僻字，勿用标点；如果分隔符失效,请自行修改)：',
                    type: 'text',
                    default: '蠔'
                },
                uploadNumber: {
                    //section: ['时间参数设置', '注意：参数设置过快，会引起115服务器无响应，为稳定运行参数未启用！'],
                    //label: '转存同时工作任务数:',
                    labelPos: 'left',
                    type: 'hidden',
                    default: '3',
                },
                uploadSleepTime: {
                    //label: '转存间隔时间（毫秒）:',
                    labelPos: 'left',
                    type: 'hidden',
                    default: '1000',
                },
                downloadNumber: {
                    //label: '提取同时工作任务数:',
                    labelPos: 'left',
                    type: 'hidden',
                    default: '3',
                },
                downloadSleepTime: {
                    //label: '提取间隔时间（毫秒）:',
                    labelPos: 'left',
                    type: 'hidden',
                    default: '2000',
                },
                createFolderSleepTime: {
                    //label: '目录创建间隔时间（毫秒）:',
                    labelPos: 'left',
                    type: 'hidden',
                    default: '600',
                },
                checkUpdate: {
                    //section: ['帮助&更新&反馈', '常见错误以及对本脚本进行更新检查与bug反馈'],
                    label: '前往github主页',
                    labelPos: 'right',
                    type: 'button',
                    click: function () {
                        window.open(TIPS.UpdateUrl, "_blank");
                    }
                },


            },

            events: {
                save: function () {
                    GM_config.close();
                    location.reload();
                }
            },
        });

        GM_registerMenuCommand('脚本与环境信息', jsInfo);

        function jsInfo() {
            postSha1Messgae(createMessage(MessageType.JSINFO, env))
        }
    };
    config();

    var currentConfig = {
        createRootFolderDefaultValue: 'createRootFolderDefaultValue',
        createChildFolderVisible: 'createChildFolderVisible',
        advancedRename: 'advancedRename',
        autoUseSeparator: 'autoUseSeparator',
        autoUseSeparatorToRename: 'autoUseSeparatorToRename',
        separator: 'separator',
        uploadNumber: 'uploadNumber',
        uploadSleepTime: 'uploadSleepTime',
        downloadNumber: 'downloadNumber',
        downloadSleepTime: 'downloadSleepTime',
        createFolderSleepTime: 'createFolderSleepTime',
        createItemSha1: 'createItemSha1',
        createItemSha1InThumb: 'createItemSha1InThumb'

    }


    var offlineTaskButton = `
    <div class="my115Dropdown" id="my115Dropdown">
    <div class="my115Dropbtn">
    <a href="javascript:;"  class="button btn-line btn-upload" menu="offline_task"><i class="icon-operate ifo-linktask"></i><span>链接与sha1转存任务</span><em style="display:none;" class="num-dot"></em></a>
    </div>
    <div class="my115Dropdown-content" style="display:none;">
      <a id="my115ContinuedDownload"> 继续【提取】或者【转存】</a>
    </div>
  </div>
    `;

    if (!$("#my115Dropdown").length > 0) {

        $(".left-tvf").eq(0).append(offlineTaskButton);
        $("#my115ContinuedDownload").click(e => {
            postSha1Messgae(createMessage(MessageType.BEGIN4CONTINUETASK, ""));
        });
    }


    window.cookie = document.cookie


    //todo:添加的功能入口 
    //列表模式下，项目悬工具条
    waitForKeyElements("div.file-opr", AddShareSHA1Btn);
    //添加任务的弹窗
    waitForKeyElements("div.dialog-bottom", AddDownloadSha1Btn);
    //搜索下的状态
    waitForKeyElements("div.lstc-search", AddShareButtonForSearchItem);
    //缩略图模式下
    waitForKeyElements(`#js_cantain_box .list-thumb li[rel="item"]`, AddCeateSha1ButtonInGrid)
    //文件路径旁边的”选中获取项sha1“
    waitForKeyElements('div#js_top_header_file_path_box', CreateSha1ButtonForSelectedItems);
    //隐藏截图中的uid
    waitForKeyElements('div[class^="fp-"]', HandleUidDiv);
    //将所有点结尾的文件设置为可播放
    waitForKeyElements(".list-contents", (function(){ $(".list-contents > ul > li").each(function(i, item) {if($(this).attr('title').substr(-1) == '.'){$(this).attr('iv',1);}});}));
 
    function HandleUidDiv(node) {
        node.hide();
        console.log("set uiddiv");
    }

    //#region 20201230新的提取api相关
    var pub_key = '-----BEGIN PUBLIC KEY-----\
    MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR3rWmeYnRClwLBB0Rq0dlm8Mr\
    PmWpL5I23SzCFAoNpJX6Dn74dfb6y02YH15eO6XmeBHdc7ekEFJUIi+swganTokR\
    IVRRr/z16/3oh7ya22dcAqg191y+d6YDr4IGg/Q5587UKJMj35yQVXaeFXmLlFPo\
    kFiz4uPxhrB7BGqZbQIDAQAB\
    -----END PUBLIC KEY-----'
    var private_key = '-----BEGIN RSA PRIVATE KEY-----\
    MIICXAIBAAKBgQCMgUJLwWb0kYdW6feyLvqgNHmwgeYYlocst8UckQ1+waTOKHFC\
    TVyRSb1eCKJZWaGa08mB5lEu/asruNo/HjFcKUvRF6n7nYzo5jO0li4IfGKdxso6\
    FJIUtAke8rA2PLOubH7nAjd/BV7TzZP2w0IlanZVS76n8gNDe75l8tonQQIDAQAB\
    AoGANwTasA2Awl5GT/t4WhbZX2iNClgjgRdYwWMI1aHbVfqADZZ6m0rt55qng63/\
    3NsjVByAuNQ2kB8XKxzMoZCyJNvnd78YuW3Zowqs6HgDUHk6T5CmRad0fvaVYi6t\
    viOkxtiPIuh4QrQ7NUhsLRtbH6d9s1KLCRDKhO23pGr9vtECQQDpjKYssF+kq9iy\
    A9WvXRjbY9+ca27YfarD9WVzWS2rFg8MsCbvCo9ebXcmju44QhCghQFIVXuebQ7Q\
    pydvqF0lAkEAmgLnib1XonYOxjVJM2jqy5zEGe6vzg8aSwKCYec14iiJKmEYcP4z\
    DSRms43hnQsp8M2ynjnsYCjyiegg+AZ87QJANuwwmAnSNDOFfjeQpPDLy6wtBeft\
    5VOIORUYiovKRZWmbGFwhn6BQL+VaafrNaezqUweBRi1PYiAF2l3yLZbUQJAf/nN\
    4Hz/pzYmzLlWnGugP5WCtnHKkJWoKZBqO2RfOBCq+hY4sxvn3BHVbXqGcXLnZPvo\
    YuaK7tTXxZSoYLEzeQJBAL8Mt3AkF1Gci5HOug6jT4s4Z+qDDrUXo9BlTwSWP90v\
    wlHF+mkTJpKd5Wacef0vV+xumqNorvLpIXWKwxNaoHM=\
    -----END RSA PRIVATE KEY-----'

    const priv = forge.pki.privateKeyFromPem(private_key);
    const pub = forge.pki.publicKeyFromPem(pub_key);
    const g_key_l = [0x42, 0xda, 0x13, 0xba, 0x78, 0x76, 0x8d, 0x37, 0xe8, 0xee, 0x04, 0x91]
    const g_key_s = [0x29, 0x23, 0x21, 0x5e]
    const g_kts = [0xf0, 0xe5, 0x69, 0xae, 0xbf, 0xdc, 0xbf, 0x5a, 0x1a, 0x45, 0xe8, 0xbe, 0x7d, 0xa6, 0x73, 0x88, 0xde, 0x8f, 0xe7, 0xc4, 0x45, 0xda, 0x86, 0x94, 0x9b, 0x69, 0x92, 0x0b, 0x6a, 0xb8, 0xf1, 0x7a, 0x38, 0x06, 0x3c, 0x95, 0x26, 0x6d, 0x2c, 0x56, 0x00, 0x70, 0x56, 0x9c, 0x36, 0x38, 0x62, 0x76, 0x2f, 0x9b, 0x5f, 0x0f, 0xf2, 0xfe, 0xfd, 0x2d, 0x70, 0x9c, 0x86, 0x44, 0x8f, 0x3d, 0x14, 0x27, 0x71, 0x93, 0x8a, 0xe4, 0x0e, 0xc1, 0x48, 0xae, 0xdc, 0x34, 0x7f, 0xcf, 0xfe, 0xb2, 0x7f, 0xf6, 0x55, 0x9a, 0x46, 0xc8, 0xeb, 0x37, 0x77, 0xa4, 0xe0, 0x6b, 0x72, 0x93, 0x7e, 0x51, 0xcb, 0xf1, 0x37, 0xef, 0xad, 0x2a, 0xde, 0xee, 0xf9, 0xc9, 0x39, 0x6b, 0x32, 0xa1, 0xba, 0x35, 0xb1, 0xb8, 0xbe, 0xda, 0x78, 0x73, 0xf8, 0x20, 0xd5, 0x27, 0x04, 0x5a, 0x6f, 0xfd, 0x5e, 0x72, 0x39, 0xcf, 0x3b, 0x9c, 0x2b, 0x57, 0x5c, 0xf9, 0x7c, 0x4b, 0x7b, 0xd2, 0x12, 0x66, 0xcc, 0x77, 0x09, 0xa6]
    var m115_l_rnd_key = genRandom(16)
    var m115_s_rnd_key = []
    var key_s = []
    var key_l = []

    function intToByte(i) {
        var b = i & 0xFF;
        var c = 0;
        if (b >= 256) {
            c = b % 256;
            c = -1 * (256 - c);
        } else {
            c = b;
        }
        return c
    }

    function stringToArray(s) {
        var map = Array.prototype.map
        var array = map.call(s, function (x) {
            return x.charCodeAt(0);
        })
        return array
    }

    function arrayTostring(array) {
        var result = "";
        for (var i = 0; i < array.length; ++i) {
            result += (String.fromCharCode(array[i]));
        }
        return result;
    }

    function m115_init() {
        key_s = []
        key_l = []
    }

    function m115_setkey(randkey, sk_len) {
        var length = sk_len * (sk_len - 1)
        var index = 0
        var xorkey = ''
        if (randkey) {
            for (var i = 0; i < sk_len; i++) {
                var x = intToByte((randkey[i]) + (g_kts[index]))
                xorkey += String.fromCharCode(g_kts[length] ^ x)
                length -= sk_len
                index += sk_len
            }
            if (sk_len == 4) {
                key_s = stringToArray(xorkey)
            } else if (sk_len == 12) {
                key_l = stringToArray(xorkey)
            }
        }
    }

    function xor115_enc(src, key) {
        var lkey = key.length
        var secret = []
        var num = 0
        var pad = (src.length) % 4
        if (pad > 0) {
            for (var i = 0; i < pad; i++) {
                secret.push((src[i]) ^ key[i])
            }
            src = src.slice(pad)
        }
        for (var j = 0; j < src.length; j++) {
            if (num >= lkey) {
                num = num % lkey
            }
            secret.push((src[j] ^ key[num]))
            num += 1
        }
        return secret

    }

    function genRandom(len) {
        var keys = []
        var chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz23456789';
        var maxPos = chars.length;
        for (var i = 0; i < len; i++) {
            keys.push(chars.charAt(Math.floor(Math.random() * maxPos)).charCodeAt(0));
        }
        return keys;
    }

    function m115_encode(plaintext) {
        //console.log('m115_encode:')
        m115_init()
        key_l = g_key_l
        m115_setkey(m115_l_rnd_key, 4)
        var tmp = xor115_enc(stringToArray(plaintext), key_s).reverse()
        var xortext = xor115_enc(tmp, key_l)
        var text = arrayTostring(m115_l_rnd_key) + arrayTostring(xortext)
        var ciphertext = pub.encrypt(text)
        ciphertext = encodeURIComponent(forge.util.encode64(ciphertext))
        return ciphertext
    }

    function m115_decode(ciphertext) {
        //console.log('m115_decode:')
        var bciphertext = forge.util.decode64(ciphertext)
        var block = bciphertext.length / (128)
        var plaintext = ''
        var index = 0
        for (var i = 1; i <= block; ++i) {
            plaintext += priv.decrypt(bciphertext.slice(index, i * 128))
            index += 128
        }
        m115_s_rnd_key = stringToArray(plaintext.slice(0, 16))
        plaintext = plaintext.slice(16);
        m115_setkey(m115_l_rnd_key, 4)
        m115_setkey(m115_s_rnd_key, 12)
        var tmp = xor115_enc(stringToArray(plaintext), key_l).reverse()
        plaintext = xor115_enc(tmp, key_s)
        return arrayTostring(plaintext)
    }

    function PostData(dict) {
        var k, tmp, v;
        tmp = [];
        for (k in dict) {
            v = dict[k];
            tmp.push(k + "=" + v);
        }
        return tmp.join('&');
    };

    function UrlData(dict) {
        var k, tmp, v;
        tmp = [];
        for (k in dict) {
            v = dict[k];
            tmp.push((encodeURIComponent(k)) + "=" + (encodeURIComponent(v)));
        }
        return tmp.join('&');
    };

    function GetSig(userid, fileid, target, userkey) {
        var sha1, tmp;
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userid + fileid + fileid + target + "0");
        tmp = sha1.getHash('HEX');
        sha1 = new jsSHA('SHA-1', 'TEXT');
        sha1.update("" + userkey + tmp + "000000");
        return sha1.getHash('HEX', {
            outputUpper: true
        });
    }



    function download(filename, content, contentType) {
        if (!contentType) contentType = 'application/octet-stream';
        var a = document.createElement('a');
        var blob = new Blob([content], {
            'type': contentType
        });
        a.href = window.URL.createObjectURL(blob);
        a.download = filename;
        a.click();
    }

    function RenewCookie() {
        var arryCookie = window.cookie.split(';');
        arryCookie.forEach(function (kv) {
            document.cookie = kv + ";expires=Thu, 01 Jan 2100 00:00:00 UTC;;domain=.115.com"
        })
    }

    function DeleteCookie(resp) {
        try {
            var reg = /set-cookie: .+;/g;
            var setcookie = reg.exec(resp)[0].split(';');
            var filecookie = setcookie[0].slice(11) + "; expires=Thu, 01 Jan 1970 00:00:00 UTC;" + setcookie[3] + ";domain=.115.com";
            document.cookie = filecookie;
            RenewCookie()
            return filecookie;
        } catch (err) {
            return null;
        }
    }




    //#endregion

    function hereDoc(f) {
        return f.toString().replace(/^[^\/]+\/\*!?\s?/, '').replace(/\*\/[^\/]+$/, '');
    }

    const TaskType = {
        DOWNLOAD: 'Download', //提取
        UPLOAD: 'Upload', //转存
    };

    const MessageType = {
        BEGIN: 0,
        PROCESSING: 1,
        END: 2,
        ERROR: 3,
        CLOSE: 4,
        CANCEL: 5,
        BEGIN4UPLOAD: 6,
        END4UPLOAD: 7,
        NOTIFYINFO: 8,
        BEGIN4CONTINUETASK: 9,
        SHOWCANCEl: 10,
        HIDECANCEL: 11,
        FILEDOWNLOAD: 12,
        MSGERROR: 13,
        JSINFO: 14,
        FATALERRORUPLOAD:15
    };

    function createMessage(messageType, msg, id) {
        return {
            messageType: messageType,
            msg: msg,
            targetID: id
        }
    }

    String.prototype.format = function () {
        if (arguments.length == 0) {
            return this;
        }
        for (var s = this, i = 0; i < arguments.length; i++) {
            s = s.replace(new RegExp("\\{" + i + "\\}", "g"), arguments[i]);
        }
        return s;
    };

    var getTamplateLines = function () {
        /*
            <div >
                <div class="itemContent" style="color: red;text-align: left;margin: 10px 0;">
                </div>
                <hr />
                <div style="height:140px;overflow-x: hidden;overflow-y: auto;">
                    <ul class="errorList"  style="font-size: small;text-align: left;font-style: italic; "></ul>
                </div>
            </div>
        */
    };


    //post from iframe
    function postSha1Messgae(message) {
        var postData = {
            eventID: "115sha1",
            data: message
        };

        var text = JSON.stringify(postData);
        window.parent.postMessage(text, "https://115.com/");

    }

    function setTaskCancel() {
        GM_setValue("setTaskCancel", true)
    }

    function resetTaskCancelFlag() {
        GM_setValue("setTaskCancel", false)
    }

    function getTaskCancelFlag() {
        return GM_getValue("setTaskCancel");
    }

    const footerString = `<p class="rainbow-text"><span style="color:#2777F8">[${TIPS.CurrentVersion}]</span>: 操作时，<span class="my115Info">确保本页面置顶</span>，防止脚本休眠！！
    <br><span class="my115Info">无</span>115会员，<span class="my115Info">提取速度</span>受限，<span class="my115Info">转存文件大小</span>不超过5GB！！</p>`;
    //解决提取时的alert不能全屏的问题
    if (window.top === window.self) {
        $(function () {
            var $itemContent = null;
            var $errorList = null;
            var getTamplate = hereDoc(getTamplateLines);

            $(window).on("message", function (e) {
                var dataInfo = typeof e.originalEvent.data == "string" ? JSON.parse(e.originalEvent.data) : e.originalEvent.data;
                if (dataInfo.eventID != "115sha1" || e.originalEvent.origin != "https://115.com") return;
                var message = typeof dataInfo.data == "string" ? JSON.parse(dataInfo.data) : dataInfo.data;

                //ui:
                if (message.messageType == MessageType.BEGIN) {
                    Swal.fire({
                        title: '正在操作中...',
                        html: getTamplate,
                        allowOutsideClick: false,
                        allowEscapeKey: false,
                        confirmButtonText: `完成`,
                        showCancelButton: true,
                        cancelButtonText: `取消操作`,
                        footer: footerString,
                        willOpen: function () {
                            Swal.getCancelButton().style.display = "none";
                            Swal.showLoading(Swal.getConfirmButton());
                            var $swalContent1 = $(Swal.getHtmlContainer());
                            $errorList = $swalContent1.find(".errorList");
                            $itemContent = $swalContent1.find(".itemContent");
                        }
                    }).then((result) => {
                        if (result.dismiss === Swal.DismissReason.cancel) {
                            setTaskCancel();
                            console.log("Download Cancel Task");
                            Swal.fire({
                                title: '已取消，等待进行中的任务结束...',
                                html: getTamplate,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                confirmButtonText: `完成`,
                                footer: footerString,
                                willOpen: function () {
                                    Swal.showLoading(Swal.getConfirmButton());
                                    var $swalContent1 = $(Swal.getHtmlContainer());
                                    let html = $errorList.eq[0];
                                    $errorList = $swalContent1.find(".errorList");
                                    $errorList.append(html);
                                    $itemContent = $swalContent1.find(".itemContent");
                                }
                            })
                        }
                    });

                } else if (message.messageType == MessageType.PROCESSING) {
                    $itemContent.html(message.msg);
                } else if (message.messageType == MessageType.ERROR) {
                    $errorList.append('<li><div display: flex;"><p>' + message.msg + '</p><p style="font-style: italic;"><\p><\div><\li><li><hr/></li>');
                } else if (message.messageType == MessageType.END) {
                    $itemContent.html(message.msg);
                    Swal.getTitle().textContent = "操作完成！";
                    Swal.getCancelButton().style.display = "none";
                    Swal.getFooter().style.display = "none";
                    Swal.hideLoading();

                } else if (message.messageType == MessageType.CLOSE) {
                    Swal.close();
                } else if (message.messageType == MessageType.BEGIN4UPLOAD) {
                    Swal.fire({
                        title: '正在操作中...',
                        html: getTamplate,
                        allowOutsideClick: false,
                        allowEscapeKey: false,
                        confirmButtonText: `完成`,
                        denyButtonText: `打开目录`,
                        showCancelButton: true,
                        cancelButtonText: "取消操作",
                        footer: footerString,
                        willOpen: function () {
                            Swal.getCancelButton().style.display = "none";
                            Swal.getDenyButton().style.display = "none";
                            Swal.showLoading(Swal.getConfirmButton());
                            var $swalContent1 = $(Swal.getHtmlContainer());
                            $errorList = $swalContent1.find(".errorList");
                            $itemContent = $swalContent1.find(".itemContent");
                        }
                    }).then(result => {
                        if (result.dismiss === Swal.DismissReason.cancel) {
                            setTaskCancel();
                            console.log("Upload Cancel Task");
                            console.log(window.parent.document.myData)
                            Swal.fire({
                                title: '已取消，等待进行中的任务完成...',
                                html: getTamplate,
                                allowOutsideClick: false,
                                allowEscapeKey: false,
                                confirmButtonText: `完成`,
                                denyButtonText: `打开目录`,
                                showCancelButton: false,
                                cancelButtonText: "取消操作",
                                willOpen: function () {

                                    Swal.getDenyButton().style.display = "none";
                                    Swal.showLoading(Swal.getConfirmButton());
                                    var $swalContent1 = $(Swal.getHtmlContainer());
                                    $errorList = $swalContent1.find(".errorList");
                                    $itemContent = $swalContent1.find(".itemContent");
                                }
                            });



                        }
                    });
                } else if(message.messageType == MessageType.FATALERRORUPLOAD){
                    $itemContent.html(message.msg);
                    Swal.getTitle().textContent = "上传遇到致命错误，已主动停止！";
                    Swal.getCancelButton().style.display = "none";
                    Swal.getDenyButton().style.display = "block";
                    Swal.getDenyButton().addEventListener('click', e => {
                        console.log("DenyButton click");
                        console.log(message);
                        window.location.href = "https://115.com/?cid=" + message.targetID + "&offset=0&tab=&mode=wangpan";
                    });
                    Swal.getFooter().style.display = "none";
                    Swal.hideLoading();
                }
                else if (message.messageType == MessageType.END4UPLOAD) {
                    $itemContent.html(message.msg);
                    Swal.getTitle().textContent = "操作完成！";
                    Swal.getCancelButton().style.display = "none";
                    Swal.getDenyButton().style.display = "block";
                    Swal.getDenyButton().addEventListener('click', e => {
                        console.log("DenyButton click");
                        console.log(message);
                        window.location.href = "https://115.com/?cid=" + message.targetID + "&offset=0&tab=&mode=wangpan";
                    });
                    Swal.getFooter().style.display = "none";
                    Swal.hideLoading();
                } else if (message.messageType == MessageType.BEGIN4CONTINUETASK) {
                    let taskFile = '';
                    Swal.fire({
                        title: '导入任务文件，继续任务',
                        html: `<div style="text-align: left;">
                        选择任务文件(.7task)：<input id="continuedTaskFile" type="file" accept=".7task" ></input>
                        <div style="font-size:14px;color:red;margin:10px;text-align: left;">*在没有移动相关的文件以及文件夹，包括目标的所有目录层级，导入任务可继续</div>
                      </div>`,
                        focusConfirm: false,
                        confirmButtonText: `开始继续任务`,
                    }).then(t => {
                        if (t.isConfirmed && taskFile) {
                            ContinuedTask(taskFile);
                        }
                    })

                    document.getElementById('continuedTaskFile').addEventListener('change', e => {
                        taskFile = e.target.files[0];
                    })

                } else if (message.messageType == MessageType.SHOWCANCEl) {
                    if (Swal.getCancelButton()) {
                        //Swal.getCancelButton().style.display = "block";
                    }
                } else if (message.messageType == MessageType.HIDECANCEL) {
                    if (Swal.getCancelButton()) {
                        Swal.getCancelButton().style.display = "none";
                    }

                } else if (message.messageType == MessageType.FILEDOWNLOAD) {
                    console.log(message.msg)
                    let size = parseInt(message.msg.onlineFile.size);
                    if (size > 2 * 1024 * 1024) {
                        postSha1Messgae(createMessage(MessageType.MSGERROR, "暂不支持大于2MB的 text|json 文件！"));
                    } else {
                        Swal.fire({
                            title: '正在下载文件...',
                            html: `<p>${message.msg.onlineFile.name}</p><p id="processInSwal"></p>`,
                            allowOutsideClick: false,
                            allowEscapeKey: false,
                            confirmButtonText: `完成`,
                            showCancelButton: false,
                            willOpen: function () {
                                Swal.showLoading(Swal.getConfirmButton());
                                downloadAFile(message.msg.onlineFile, text => {
                                    $(Swal.getHtmlContainer()).find("#processInSwal").html(text);
                                }).then(r => {
                                    if (r.state) {
                                        console.log(r.text)
                                        message.msg.config.text = r.text;

                                        UploadFilesBySha1Links(message.msg.config);
                                    }
                                });

                            }
                        })
                    }

                } else if (message.messageType == MessageType.MSGERROR) {
                    Swal.fire({
                        icon: 'error',
                        text: message.msg,
                    })
                } else if (message.messageType == MessageType.JSINFO) {
                    Swal.fire({
                        icon: 'info',
                        text: '脚本与环境信息：（如果报bug，请附带上如下信息）\r\n' + message.msg,
                    })
                }


            })
        });
    }






    function delay(ms) {

        if (ms == 0) {
            ms = 1000 * (Math.floor(Math.random() * (11 - 4)) + 4);
        }
        return new Promise(resolve => setTimeout(resolve, ms))
    }


    //#region 115 api
    //get   UploadInfo
    //return {state:false,user_id:0,userkey:'0',error:''}
    async function getUploadInfo() {
        const r = await $.ajax({
            url: 'https://proapi.115.com/app/uploadinfo',
            dataType: 'json',
            xhrFields: {
                withCredentials: true
            }
        });
        return r;
    }

    //add a folder
    //return {state: false, error: "该目录名称已存在。", errno: 20004, errtype: "war"}
    //return {state: true, error: "", errno: "", aid: 1, cid: "2020455078010511975", …}
    async function addFolder(pid, folderName) {
        const postData = PostData({
            pid: pid,
            cname: encodeURIComponent(folderName)
        });

        const r = await $.ajax({
            type: 'POST',
            url: 'https://webapi.115.com/files/add',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                //'Origin': 'https://115.com'
            },
            xhrFields: {
                withCredentials: true
            },
            dataType: 'json',
            data: postData
        });

        return r;
    }


    //return {data: Array(30), count: 53, data_source: "DB", sys_count: 0, offset: 0, page_size:115, …}
    //return Array type:
    //      [folder]:{cid: "", aid: "1", pid: "", n: "", m: 0, …}
    //      [file]:  {fid: "", uid: 1447812, aid: 1, cid: "", n: "",pc:"",sha:"",s:0,t:"" …}
    async function getDirectChildItemsByOffset(cid, offset) {
        var tUrl = 'https://webapi.115.com/files?aid=1&cid=' + cid + '&o=file_name&asc=1&offset=' + offset + '&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&fc_mix=&type=&star=&is_share=&suffix=&custom_order=';
        // var tUrl = "https://aps.115.com/natsort/files.php?aid=1&cid=" + cid + "&o=file_name&asc=1&offset=" + offset + "&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&fc_mix=0&type=&star=&is_share=&suffix=&custom_order=";
        const result = await $.ajax({
            type: 'GET',
            url: tUrl,
            dataType: "json",
            xhrFields: {
                withCredentials: true
            }
        });
        return result;
    }

    //直接子项目少于1200
    async function getDirectChildItemsByOffsetlt1200(cid, offset) {
        //var tUrl = 'https://webapi.115.com/files?aid=1&cid='+cid+'&o=file_name&asc=1&offset='+offset+'&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&fc_mix=&type=&star=&is_share=&suffix=&custom_order=';
        var tUrl = "https://aps.115.com/natsort/files.php?aid=1&cid=" + cid + "&o=file_name&asc=1&offset=" + offset + "&show_dir=1&limit=1150&code=&scid=&snap=0&natsort=1&record_open_time=1&source=&format=json&fc_mix=0&type=&star=&is_share=&suffix=&custom_order=";
        const result = await $.ajax({
            type: 'GET',
            url: tUrl,
            dataType: "json",
            xhrFields: {
                withCredentials: true
            }
        });
        return result;
    }

    //return AllDirect items :{id:"",parentID:cid,isFolder:false,name:"",size:0,pc:"",sha:"",paths[] };
    async function getAllDirectItems(cid, folderProcessCallback) {
        var items = new Array();
        var index = 0;
        var flag = true;
        var pageIndex = 1;
        var first = true;
        var isLT1200 = false;

        while (flag) {
            if (getTaskCancelFlag()) break;

            folderProcessCallback(pageIndex);
            var result = null;
            //1200数量，不同的api；这么写减少发包  
            if (first) {
                result = await getDirectChildItemsByOffset(cid, index);
                console.log(`first >1200 :${result.state},${result.count}`);
                if (!result.state) {
                    result = await getDirectChildItemsByOffsetlt1200(cid, index);
                    console.log(`first <1200 :${result.state},${result.count}`);
                    isLT1200 = true;
                }
                first = false;
            } else {
                if (isLT1200) result = await getDirectChildItemsByOffsetlt1200(cid, index);
                else result = await getDirectChildItemsByOffset(cid, index);
            }

            var totalCount = parseInt(result.count);
            if (totalCount >= 1) {
                result.data.forEach(function (item) {
                    var pItem = {
                        id: "",
                        parentID: cid,
                        isFolder: false,
                        name: "",
                        size: "",
                        pickCode: "",
                        sha1: "",
                        paths: new Array(),
                        preid: "",
                        needToRemoved: false
                    };

                    if (item.fid) //文件 fid,cid
                    {
                        pItem.isFolder = false;
                        pItem.id = item.fid;
                        pItem.name = item.n;
                        pItem.pickCode = item.pc;
                        pItem.sha1 = item.sha;
                        pItem.size = item.s;
                    } else //目录 cid,pid
                    {
                        pItem.isFolder = true;
                        pItem.id = item.cid;
                        pItem.name = item.n;
                        pItem.pickCode = item.pc;
                    }


                    var itemIndex = items.findIndex(q => q.name == pItem.name && q.pickCode == pItem.pickCode && q.sha1 == pItem.sha1 && (_.isEqual(q.paths, pItem.paths)));
                    if (itemIndex == -1) items.push(pItem);
                    else {
                        //可能存在同一个目录下，两个文件一模一样,
                        //相同文件处理：不然循环条件退不出
                        //fix:pickcode不一样,先保存着吧
                        pItem.needToRemoved = true;
                        items.push(pItem)
                    }
                })
            }

            console.log("_______________totalCount " + totalCount);
            console.log(items.length)
            //当获取到比pagesize小时，获取结束,1200时有个坑。。。
            if (totalCount <= items.length) {
                break;
            } else {
                await delay(500);
                index = items.length;
                pageIndex = pageIndex + 1;
            }
        }

        console.log("cid: {0}, count: {1}".format(cid, items.length));

        var noNullItems = items.filter(q => !q.needToRemoved);
        console.log("cid: {0}, 除去完全重复count: {1}".format(cid, noNullItems.length));

        return noNullItems;
    }

    //return {file_name:"",pick_code:"",sha1:"",count:"",size:"",folder_count:"",paths:[]}
    //return paths:[]层级目录
    async function getFolderInfo(cid) {
        var pUrl = "https://webapi.115.com/category/get?aid=1&cid=" + cid;
        const result = await $.ajax({
            type: 'GET',
            url: pUrl,
            dataType: "json",
            xhrFields: {
                withCredentials: true
            }
        });
        console.log(result);
        var pItem = {
            fileCount: parseInt(result.count),
            folderCount: parseInt(result.folder_count),
            id: cid,
            parentID: "",
            isFolder: true,
            name: result.file_name,
            size: result.size,
            pickCode: result.pick_code,
            sha1: "",
            paths: result.paths,
            preid: ""
        };

        return pItem;
    }

    // get fileArray:{id:"",parentID:cid,isFolder:false,name:"",size:0,pc:"",sha:"",paths[] };
    async function getAllFiles(cid, fileArray, topCid, folderProcessCallback) {
        var thisFolder = await getFolderInfo(cid);
        folderProcessCallback(thisFolder.name, 0);
        //空目录，跳过遍历

        if (getTaskCancelFlag()) return;
        if (thisFolder.fileCount == 0) return;
        folderProcessCallback(thisFolder.name)
        var directItems = await getAllDirectItems(thisFolder.id, pageIndex => {
            folderProcessCallback(thisFolder.name, pageIndex);
        });
        //空目录，跳过遍历
        if (directItems.length == 0) return;
        var files = directItems.filter(t => !t.isFolder);
        files.forEach(f => {
            var index = thisFolder.paths.findIndex(q => q.file_id.toString() == topCid);
            var paths = new Array();
            if (index != -1) {
                paths = thisFolder.paths.slice(index).map(q => q.file_name);
            }
            paths.push(thisFolder.name);
            f.paths = paths.slice(1);

            fileArray.push(f);
        });

        var folders = directItems.filter(t => t.isFolder);
        for (var folder of folders) {
            if (getTaskCancelFlag()) break;
            await getAllFiles(folder.id, fileArray, topCid, folderProcessCallback);
            await delay(200);
        }

    }

    //批量重命名 fileArray  [{id:id,name:ddd}]
    //{"state":true,"error":"","errno":0,"data":{"2187365717527997108":"14214.mp4"}}
    async function renameFiles(fileArray) {
        console.log("renameFiles fileArray");
        console.log(fileArray);
        let datas = fileArray.map((value, index, array) => {
            let dataKey = `files_new_name[${value.id}]`;
            let dataValue = value.name;
            return `${encodeURIComponent(dataKey)}=${encodeURIComponent(dataValue)}`;
        }).join("&");

        let renameUrl = "https://webapi.115.com/files/batch_rename";
        const result = await $.ajax({
            type: 'POST',
            url: renameUrl,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                //'Origin': 'https://115.com'
            },
            dataType: "json",
            xhrFields: {
                withCredentials: true
            },
            data: datas
        });

        return result;
    }

    async function getUploadHistory(offset, limit) {
        console.log(`offset:${offset},limit:${limit}`);
        let historyFiles = [];
        let pUrl = `https://webapi.115.com/history/list?type=4&offset=${offset}&limit=${limit}`;
        const result = await $.ajax({
            type: 'GET',
            url: pUrl,
            dataType: "json",
            xhrFields: {
                withCredentials: true
            }
        });

        let files = result.data.list;
        for (const aFile of files) {
            historyFiles.push({
                sha1: aFile.sha1,
                id: aFile.file_id,
                createTime: aFile.create_time,
                pickCode: aFile.pick_code, //可能不一样
                name: aFile.file_name,
                parentID: aFile.parent_id
            });
        }

        return historyFiles;
    }

    async function getLastUploadFiles(count, delayTime = 400, processCallback) {
        let files = [];
        let offset = 0;
        let limit = 115;
        let leftCount = count;
        while (leftCount >= limit) {
            processCallback(`正在获取第${offset + 1}-${offset + limit + 1}个文件数据...`)
            let result = await getUploadHistory(offset, limit);
            result.forEach(f => files.push(f));
            offset = offset + limit;
            leftCount = leftCount - limit;
            await delay(delayTime);
        }

        if (leftCount > 0) {
            processCallback(`正在获取第${offset + 1}-${offset + leftCount + 1}个文件数据...`)
            let result = await getUploadHistory(offset, leftCount);
            result.forEach(f => files.push(f));
            await delay(delayTime);
        }

        return files;
    }


    //获取生成sha1需要preid
    //return: {state:,error:,fileItem:}
    function getFileItemPreid(fileItem) {
        console.log('getFileItemPreid')
        console.log(fileItem);
        const f = fileItem;
        let fileSize = parseInt(fileItem.size);
        if (fileSize == 0) {
            return new Promise((resolve, reject) => {
                const errorMsg = "{0} 文件大小为0，已经跳过！".format(f.filename);
                console.error("errorMsg");
                resolve({
                    state: false,
                    error: "文件大小为0，已经跳过！",
                    fileItem: fileItem
                });
            });
        }

        const r = new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: "POST",
                url: 'https://proapi.115.com/app/chrome/downurl',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 115Browser/23.9.3.6'
                },
                responseType: 'json',
                data: PostData({
                    data: m115_encode('{"pickcode":"' + fileItem.pickCode + '"}')
                }),
                onload: function (r) {
                    if (r.status == 200) {
                        var download_info = r.response;


                        if (download_info.state && download_info.data) {
                            try {
                                var json = m115_decode(download_info.data);
                                //console.log(json)
                                var url = JSON.parse(json)[fileItem.id]['url']['url'];
                                //todo:不能下载的文件处理
                                if (!url.startsWith("http://cdnfhnfdfs.115.com") && url.startsWith('http:///')) {
                                    console.error(`error url:${url}`);
                                    url = url.replace("http:///", "http://cdnfhnfdfs.115.com/")
                                }

                                console.log(url);
                                var resp = r.responseHeaders
                                var setCookie = DeleteCookie(resp)
                                var fileCookie = null;
                                if (setCookie) {
                                    fileCookie = setCookie;
                                }

                                GM_xmlhttpRequest({
                                    method: "GET",
                                    url: url,
                                    timeout: 12000,
                                    headers: {
                                        "Range": "bytes=0-131072",
                                        "Cookie": fileCookie,
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 115Browser/23.9.3.6'
                                    },
                                    responseType: 'arraybuffer',
                                    onload: function (response) {
                                        if (response.status === 206) {
                                            var pre_buff = response.response;
                                            var data = new Uint8Array(pre_buff);
                                            var sha1 = new jsSHA('SHA-1', 'ARRAYBUFFER');
                                            sha1.update(data.slice(0, 128 * 1024));
                                            var preid = sha1.getHash('HEX', {
                                                outputUpper: true
                                            });
                                            fileItem.preid = preid;
                                            resolve({
                                                state: true,
                                                error: "",
                                                fileItem: fileItem
                                            });
                                        } else if (response.status === 403) {
                                            console.error("Forbidden, 已经用40个0代替");
                                            fileItem.preid = "0000000000000000000000000000000000000000";
                                            resolve({
                                                state: true,
                                                error: "",
                                                fileItem: fileItem
                                            });
                                        } else {
                                            //fix v3.3:  修复404文件无法下载导致卡ui问题  @指环王
                                            console.error("可能文件无法下载或者网络问题");
                                            console.log(response);
                                            resolve({
                                                state: false,
                                                error: "下载出错，可能文件无法下载或者网络问题",
                                                fileItem: fileItem
                                            });
                                        }
                                    },
                                    ontimeout: function (res) {
                                        console.error("下载超时，可能文件无法下载或者网络问题");
                                        console.log(res);
                                        resolve({
                                            state: false,
                                            error: "下载超时，可能文件无法下载或者网络问题",
                                            fileItem: fileItem
                                        });
                                    }
                                });
                            } catch (error) {
                                console.error(error);
                                resolve({
                                    state: false,
                                    error: "在提取中发生错误...",
                                    fileItem: fileItem
                                });
                            }
                        } else {
                            console.log(download_info);
                            resolve({
                                state: false,
                                error: download_info.msg,
                                fileItem: fileItem
                            });
                        }

                    } else {
                        console.error(response.response);
                        resolve({
                            state: false,
                            error: "在提取中发生错误...",
                            fileItem: fileItem
                        });
                    }
                }
            });
        });
        return r;
    }


    var utf8ArrayToStr = (function () {
        var charCache = new Array(128); // Preallocate the cache for the common single byte chars
        var charFromCodePt = String.fromCodePoint || String.fromCharCode;
        var result = [];

        return function (array) {
            var codePt, byte1;
            var buffLen = array.length;

            result.length = 0;

            for (var i = 0; i < buffLen;) {
                byte1 = array[i++];

                if (byte1 <= 0x7F) {
                    codePt = byte1;
                } else if (byte1 <= 0xDF) {
                    codePt = ((byte1 & 0x1F) << 6) | (array[i++] & 0x3F);
                } else if (byte1 <= 0xEF) {
                    codePt = ((byte1 & 0x0F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
                } else if (String.fromCodePoint) {
                    codePt = ((byte1 & 0x07) << 18) | ((array[i++] & 0x3F) << 12) | ((array[i++] & 0x3F) << 6) | (array[i++] & 0x3F);
                } else {
                    codePt = 63; // Cannot convert four byte code points, so use "?" instead
                    i += 3;
                }

                result.push(charCache[codePt] || (charCache[codePt] = charFromCodePt(codePt)));
            }

            return result.join('');
        };
    })();

    function downloadAFile(fileItem, progressCallback = function (text) { }) {
        console.log("downloadAFile")
        console.log(fileItem)
        const r = new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: "POST",
                url: 'https://proapi.115.com/app/chrome/downurl',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 115Browser/23.9.3.6'
                },
                responseType: 'json',
                data: PostData({
                    data: m115_encode('{"pickcode":"' + fileItem.pickCode + '"}')
                }),
                onload: function (r) {
                    if (r.status == 200) {
                        var download_info = r.response;
                        if (download_info.state && download_info.data) {
                            try {
                                var json = m115_decode(download_info.data);
                                //console.log(json)
                                var url = JSON.parse(json)[fileItem.id]['url']['url'];
                                //todo:不能下载的文件处理
                                if (!url.startsWith("http://cdnfhnfdfs.115.com") && url.startsWith('http:///')) {
                                    console.error(`error url:${url}`);
                                    url = url.replace("http:///", "http://cdnfhnfdfs.115.com/")
                                }

                                console.log(url);
                                var resp = r.responseHeaders
                                var setCookie = DeleteCookie(resp)
                                var fileCookie = null;
                                if (setCookie) {
                                    fileCookie = setCookie;
                                }

                                GM_xmlhttpRequest({
                                    method: "GET",
                                    url: url,
                                    headers: {
                                        "Content-Type": "application/octet-stream",
                                        "Cookie": fileCookie,
                                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.61 Safari/537.36 115Browser/23.9.3.6'
                                    },
                                    responseType: 'arraybuffer',
                                    onload: function (response) {
                                        if (response.status === 200) {
                                            let str = utf8ArrayToStr(new Uint8Array(response.response));
                                            resolve({
                                                state: true,
                                                error: "",
                                                text: str
                                            });
                                        } else {

                                            console.error(response);
                                            resolve({
                                                state: false,
                                                error: `response.status:${response.status}`,
                                                text: ""
                                            });

                                        }

                                    },
                                    onprogress: function (event) {
                                        let textMsg = `${event.loaded} of ${event.total} bytes, ${(event.loaded / event.total).toFixed(4) * 100}%`;
                                        console.log(textMsg);
                                        progressCallback(textMsg)
                                    }

                                });
                            } catch (error) {
                                console.error(error);
                                resolve({
                                    state: false,
                                    error: `${error}`,
                                    text: ""
                                });

                            }
                        } else {
                            console.log(download_info);
                            resolve({
                                state: false,
                                error: download_info.msg,
                                text: ""
                            });
                        }

                    } else {
                        console.log("下载第一阶段")
                        console.error(response.response);
                        resolve({
                            state: false,
                            error: `在下载中发生错误...${response.status}`,
                            text: ""
                        });
                    }
                }
            });
        });
        return r;
    }

    function replaceDot(name) {
        return name.replace(/\./g, "_");
    }
    //windows平台上限制的字符：/\|":*?<> 其他平台比windows宽泛一些
    function repalceValidatedName(name) {
        return name.replace(/</g, '[')
            .replace(/>/g, ']')
            .replace(/\|/g, '_')
            .replace(/:/g, '_')
            .replace(/\//g, '_')
            .replace(/\\/g, '_')
            .replace(/\*/g, '_')
            .replace(/"/g, '\'')
            .replace(/\?/g, '_');
    }
    //格式化sha1 链接
    //return type: {state:succeed,msg:""}
    // false:msg->出错信息
    //true: msg->sha1链接 
    function convertToSha1Link(fileItem, isSimpleFormat) {
        var succeed = false;
        var msg = "格式生成失败!";
        if (fileItem.name && fileItem.size && fileItem.sha1 && fileItem.preid) {
            var sha1Link = "115://" + repalceValidatedName(fileItem.name) + "|" + fileItem.size + "|" + fileItem.sha1 + "|" + fileItem.preid;
            if (!isSimpleFormat) {
                if (fileItem.paths.length > 0) {
                    //console.log(fileItem.paths);
                    //fix: v3.3 目录中的‘|’或者‘#’替换为‘/’,防止脚本导出再导入时破坏目录结构
                    //fix: v3.4 windows平台上不能限制的字符：/\|":*?<>  替换；去掉了老版本的#分隔符
                    var paths = fileItem.paths.map(t => repalceValidatedName(t)).join('|');
                    msg = sha1Link + '|' + paths;
                } else {
                    msg = sha1Link;
                }
            } else {
                msg = sha1Link;
            }

            succeed = true;
        }
        if (!succeed) {
            console.error(fileItem);
        }

        return {
            state: succeed,
            msg: msg
        };
    }

    // 从sha1link 转换为 FileItem
    //return type:{state:succeed,fileItem:{}}
    //true: fileItem, false:null
    function convertFromSha1Link(sha1Link) {
        var succeed = false;
        var item = {};
        if (sha1Link) {
            if (sha1Link.startsWith("115://")) {
                sha1Link = sha1Link.substring(6);
            }
            //v3.4 add 转存时，文件名、文件夹名替换非法字符
            var infos = sha1Link.split('|');
            if (infos.length >= 4) {
                item.id = "";
                item.pickCode = "";
                item.name = repalceValidatedName(infos[0]);
                item.size = infos[1];
                item.sha1 = infos[2];
                item.preid = infos[3];
                item.parentID = "";
                item.paths = new Array();
                if (infos.length > 4) {
                    //fix: v3.4 移除了此兼容，因为开放了#作为目录名
                    // if (infos.length == 5 && infos[4].includes('#')) {
                    //兼容 #字符分割

                    //    item.paths = infos[4].split('#');
                    //} else {
                    item.paths = infos.slice(4).map(t => repalceValidatedName(t));
                    //}
                }
                item.extension = "";
                item.formatedName = "";
                item.formatedExtension = ""
                succeed = true;
            }
        }

        return {
            state: succeed,
            fileItem: item
        };
    }


    function createUploadFile(urlData, postData) {
        console.log("createUploadFile");
        console.log(urlData)
        return new Promise((resolve, reject) => {
            GM_xmlhttpRequest({
                method: 'POST',
                url: 'http://uplb.115.com/3.0/initupload.php?' + urlData,
                data: postData,
                responseType: 'json',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
                    //'Origin': 'https://115.com'
                },
                onload: function (response) {
                    let data = {
                        state: false,
                        error: "",
                        pickCode: "",
                        fatalError: false
                    };
                    if (response.status === 200 && response.response.status === 2) {
                        data.state = true;
                        data.pickCode = response.response.pickcode;
                    } else {
                        console.error(response);
                        let error = "或许sha1链接不匹配(?)";
                        if (response.status === 405) {
                            data.fatalError = true;
                            error = "频繁请求，被115限制 ([!]立即停止，尝试停止操作半小时或者重新登录)：" + response.statusText;
                        } else if (response.response && response.response.message) error = response.response.message;
                        else if (response.response && response.response.statusmsg) error = "可能参数不正确(?)：" + response.response.statusmsg;
                        data.error = error;
                    }
                    resolve(data);
                }
            })

        });
    }

    //return:{state:false,error:"",fileItem:};
    function uploadFile(targetFolder, fileItem, uploadInfo) {

        let fCid = `U_1_${targetFolder}`;
        let appVersion = "25.2.0";
        let urlData = UrlData({
            isp: 0,
            appid: 0,
            appversion: appVersion,
            format: 'json',
            sig: GetSig(uploadInfo.user_id, fileItem.sha1, fCid, uploadInfo.userkey)
        });

        console.log("postData")
        console.log("fileItem.formatedName")
        let postData = PostData({
            preid: fileItem.preid,
            fileid: fileItem.sha1,
            quickid: fileItem.sha1,
            app_ver: appVersion,
            filename: encodeURIComponent(fileItem.formatedName),
            filesize: fileItem.size,
            exif: '',
            target: fCid,
            userid: uploadInfo.user_id

        });

        console.log(postData)

        const r = createUploadFile(urlData, postData);

        const x = r.then(t => {
            return new Promise((resole, reject) => {
                fileItem.state = t.state;
                fileItem.pickCode = t.pickCode;
                resole({
                    fatalError: t.fatalError,
                    state: t.state,
                    error: t.error,
                    fileItem: fileItem
                });
            })
        });

        return x;
    }

    function setListView() {
        GM_xmlhttpRequest({
            method: "POST",
            url: 'https://115.com/?ct=user_setting&ac=set',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            data: PostData({
                setting: '{"view_file":"list"}'
            }),
            responseType: 'json',
            onload: function (response) {
                if (response.status === 200) { }
            }
        });
    }

    //#endregion



    async function updateParentID(cid, cname, thisLevel, maxLevel, items, sleepTime, createFolderCallback) {
        if (thisLevel == maxLevel) return;
        let files = new Array();
        if (thisLevel == 0) {
            files = items;
        } else {
            files = items.filter(f => f.paths[thisLevel - 1] == cname);
        }

        let childFiles = files.filter(q => q.paths.length == thisLevel);
        let childFolderNames = files.map(q => q.paths[thisLevel]).filter(q => q).filter((x, i, a) => a.indexOf(x) == i)

        console.log(`childFiles ：${childFiles.length}`)
        //upload file:
        for (let file of childFiles) {
            file.parentID = cid;
            //console.log(file.parentID);
        }

        //create folder:
        for (let folderName of childFolderNames) {

            let r = await createRootFolder(cid, folderName, 10, sleepTime, callbackMsg => {
                createFolderCallback && createFolderCallback({
                    state: true,
                    folderName: folderName,
                    error: callbackMsg
                });
            })

            //fix: v3.4 有同名文件夹，处理跟根目录相同处理。如果超过重试次数的逻辑未处理
            //let r = await addFolder(cid, folderName);
            console.log(r);

            if (r.state) {
                await updateParentID(r.cid, folderName, thisLevel + 1, maxLevel, files, createFolderCallback);
            } else { //ui 目录创建失败  
                //todo: ！！！尚未解决这个
                console.error(`updateParentID  如果出现这个，说明重复名字的文件夹也太太太多了`);
            }

            await delay(sleepTime);
        }

    }

    function internelFormat(folder, files, folderParents) {
        var paths = folderParents.slice(0);
        paths.push(folder.dir_name);

        for (var file of folder.files) {

            var link = file + '|' + paths.slice(1).join('|');
            files.push(link);
        }

        for (var childFolder of folder.dirs) {

            internelFormat(childFolder, files, paths)
        }
    }

    //{state:true,error:"",text:""}
    function formatJsonToCommon(text) {

        try {
            var root = JSON.parse(text);
            console.log(root);
            var files = new Array();
            var paths = new Array();
            internelFormat(root, files, paths);

            return {
                state: true,
                error: "",
                text: files.join('\r\n'),
                rootFolder: root.dir_name
            };
        } catch (error) {
            return {
                state: false,
                error: error,
                text: ""
            };
        }

    }

    function reverseString(str) {
        return str.split("").reverse().join("");
    }
    //解析inline text sha1 links,并根据配置设置分隔符;返回FileArray
    function parseSha1LinksToFileArray(text, nameSeparator, errorCallback) {
        let textLines = text.split(/\r?\n/);

        let files = new Array();
        for (let line of textLines) {
            let fLine = line.trim();
            if (!fLine) continue;
            let r = convertFromSha1Link(fLine);
            if (r.state) {
                //let nameStrings = r.fileItem.name.split(".");
                //let extension = nameStrings.pop();
                //r.fileItem.extension = extension;
                //let formatedExtension=reverseString(extension);
                //根据配置重新设置文件名
                if (nameSeparator) {
                    //使用emoutils.js库来分割，带有emoji的文件名
                    //let fileName = emojiUtils.toArray(nameStrings.join('.')).map(c => c + nameSeparator).join("").slice(0, -1);
                    //r.fileItem.formatedName = fileName + "." + formatedExtension;
                    r.fileItem.formatedName = emojiUtils.toArray(replaceDot(r.fileItem.name)).map(c => c + nameSeparator).join("").slice(0, -1);
                } else {
                    r.fileItem.formatedName = r.fileItem.name;
                }
                files.push(r.fileItem);
            } else {
                errorCallback && errorCallback(`${fLine} 格式错误?`);
            }

        }

        return files;
    }

    //fix: v3.4 时间日期中含有"/",":"导致目录或者文件下载失败
    function getCurrentTimeString() {
        let time = new Date();
        let timeString = `${time.toLocaleString()} (${time.getMilliseconds()})`;
        return timeString.replace(/\//g, ".").replace(/:/g, ".")
    }

    //在targetCid下创建目录，成功则返回新目录cid，否则返回原cid;返回’-1‘，target已经被移除或者删除
    async function createRootFolder(targetCid, folderName, retryTimes, sleepTime, processCallback) {
        let cid = targetCid;
        let newFolderName = folderName;

        if (folderName == "") {

            newFolderName = `auto_create@${getCurrentTimeString()}`;
        }

        for (let i = 0; i < retryTimes; i++) {

            if (i != 0) {

                newFolderName = `${folderName == "" ? "auto_create" : folderName}@${getCurrentTimeString()}`;
            }

            processCallback && processCallback(`正在自动创建目录${newFolderName}...`);
            let tr = await addFolder(targetCid, newFolderName);
            if (tr.state) {
                cid = tr.cid;
                processCallback && processCallback(`自动创建目录${newFolderName}成功！`);
                break;
            } else {

                processCallback && processCallback(`自动创建目录${newFolderName}失败！原因：${tr.error}，将自动尝试新的名字...`);
                if (tr.error.includes('云端目录不存在') || tr.error.includes('文件不存在或已删除')) {
                    cid = '-1'; //父目录不存在时的提示
                    break;
                }
                await delay(sleepTime);
            }
        }

        let state = cid != '-1';
        let error = state ? "" : "云端目录之前已经删除，请重新选择保存位置！"
        //todo:父目录不存在时的提示
        return {
            cid: cid,
            folderName: newFolderName,
            state: state,
            error: error
        };
    }

    function uploadFileWithTimeOut(timeOut, fileParentID, file, uploadInfo) {
        console.log('uploadFileWithTimeOut')
        let to = delay(timeOut).then(t => {
            return {
                fatalError: false,
                state: false,
                error: `等待上传结果超时，此乃警告！成功与否，看最后统计结果！`,
                fileItem: file
            }
        });
        let up = uploadFile(fileParentID, file, uploadInfo);

        return Promise.race([to, up]);
    }



    async function processUpload(allFiles, workingNumber, sleepTime, resultCallback) {
        let fileArray = allFiles.filter(q => !q.state);
        let index = 1;
        let fileLength = allFiles.length;
        let completed = fileLength - fileArray.length;
        let promisArray = new Array();
        let uploadInfo = await getUploadInfo();
        console.log("uploadInfo")
        let msg;
        let fatalError = false;
        for (let file of fileArray) {
            if (getTaskCancelFlag()) {
                console.log("转存取消");
                //postSha1Messgae(createMessage(MessageType.PROCESSING, "已取消，正在等待进行中的任务结束..."));
                break;
            }
            if (fatalError) {
                break;
            }
            console.log(file);

            //let r = uploadFile(file.parentID, file, uploadInfo).then(t => {
            let r = uploadFileWithTimeOut(8000, file.parentID, file, uploadInfo).then(t => {
                completed = completed + 1;
                if (t.state) {
                    msg = `<div align="right"><b>${completed}</b> | <b>${fileLength}</b></div><hr>【 <b>${t.fileItem.name}</b> 】上传成功.`;
                } else {
                    let uploadError = `【 <b>${t.fileItem.name}</b> 】： ${t.error}`;
                    resultCallback && resultCallback({
                        state: false,
                        msg: uploadError
                    });
                    msg = `<div align="right"><b>${completed}</b> | <b>${fileLength}</b></div><hr>${uploadError}`;

                    if (t.fatalError) {
                        console.log("fatalError");
                        fatalError = true;
                    }

                }
                resultCallback && resultCallback({
                    state: true,
                    msg: msg
                });
            });

            promisArray.push(r);

            if (index % workingNumber == 0) {
                await delay(sleepTime*1.5);
            }

            if (index % 128 == 0) {
                await Promise.all(promisArray);
                let seconds = 3;
                for (let i = 0; i < seconds; i++) {
                    resultCallback && resultCallback({
                        state: true,
                        msg: `防止115服务器限制，暂停发包。<br><br>${seconds - i}秒后继续....`
                    });
                    await delay(1000);
                }
                promisArray = new Array();
            }
            index = index + 1;
        }

        await delay(500);
        await Promise.all(promisArray);

        return fatalError;
    }


    // v3.3 转存时获取文件从历史上传中获取，如果文件夹众多，此方案速度优势明显，但不允许多页面操作
    async function processRenameByUsingHistory(files, separator, sleepTime, resultCallback) {

        let history = await getLastUploadFiles(files.length, sleepTime, t => {
            resultCallback({
                state: true,
                msg: t
            });
        });

        resultCallback({
            state: true,
            msg: "正在等待重命名...如果文件较多，请等待"
        });

        console.log(history.length);
        //console.log(history);
        //fix: v3.3.1 修复含有重复文件的时候，未所有完成重命名的bug
        history.forEach(q => q.isMarked = false);
        for (const file of files) {
            console.log(file);
            let thisFile = history.find(q => q.sha1 == file.sha1 && q.parentID == file.parentID && q.name.trim() == file.formatedName.trim() && !q.isMarked);
            //console.log("thisFile")
            //console.log(thisFile)
            if (thisFile) {
                file.id = thisFile.id;
                thisFile.isMarked = true;
            } else {
                console.error(`历史记录里未找到 ${file.name}`);
            }
        }

        let selectedFiles = files.filter(f => f.formatedName.search(separator) != -1 && f.id).map(f => {
            //let lastIndex=f.formatedName.lastIndexOf(".");
            //let name=f.formatedName.substring(0,lastIndex);
            //let ext=f.formatedName.substring(lastIndex+1);

            let fo = {
                id: f.id,
                //fix
                //name: name.split(separator).join("")+"."+reverseString(ext)
                name: f.name
            };
            return fo;
        });
        console.log(selectedFiles)
        let i, j, temporary, chunk = 115;
        for (i = 0, j = selectedFiles.length; i < j; i += chunk) {
            temporary = selectedFiles.slice(i, i + chunk);
            resultCallback && resultCallback({
                state: true,
                msg: `正在重命名第${i + 1}到${i + temporary.length}个文件...`
            });
            let renameResult = await renameFiles(temporary);
            if (renameResult.state === true) {
                resultCallback && resultCallback({
                    state: true,
                    msg: `重命名第${i + 1}到${i + temporary.length}个文件成功!`
                });
            } else {
                resultCallback && resultCallback({
                    state: false,
                    msg: renameResult.error
                });
                resultCallback && resultCallback({
                    state: true,
                    msg: `重命名第${i + 1}到${i + 1 + temporary.length}个文件中有失败！！!`
                });
            }
            await delay(sleepTime);
        }

    }



    async function processRename(targetFolderCid, separator, sleepTime, resultCallback) {
        let onlineFiles = new Array();
        await getAllFiles(targetFolderCid, onlineFiles, targetFolderCid, (fname, pIndex) => {
            if (pIndex > 1) {
                resultCallback && resultCallback({
                    state: true,
                    msg: `正在获取 【${fname}】 下第 ${pIndex} 页的内容...`
                });
            } else {
                resultCallback && resultCallback({
                    state: true,
                    msg: `正在获取 【${fname}】 下的内容...`
                });
            }
        });

        /* 20220816暂时下线手动去除分隔符，改为遍历文件夹
        let selectedFiles = onlineFiles.filter(f => f.name.search(separator) != -1).map(f => {
            //let lastIndex=f.name.lastIndexOf(".");
            //let name=f.name.substring(0,lastIndex);
            //let ext=f.name.substring(lastIndex+1);

            let fo = {
                id: f.id,
                //name: name.split(separator).join("")+"."+reverseString(ext)
                name: f.name.split(separator).join("")
            };
            return fo;
        });

        let i, j, temporary, chunk = 115;
        for (i = 0, j = selectedFiles.length; i < j; i += chunk) {
            temporary = selectedFiles.slice(i, i + chunk);
            resultCallback && resultCallback({
                state: true,
                msg: `正在重命名第${i + 1}到${i + temporary.length}个文件...`
            });
            let renameResult = await renameFiles(temporary);
            if (renameResult.state === true) {
                resultCallback && resultCallback({
                    state: true,
                    msg: `重命名第${i + 1}到${i + temporary.length}个文件成功!`
                });
            } else {
                resultCallback && resultCallback({
                    state: false,
                    msg: renameResult.error
                });
                resultCallback && resultCallback({
                    state: true,
                    msg: `重命名第${i + 1}到${i + 1 + temporary.length}个文件中有失败！！!`
                });
            }
            await delay(sleepTime);
        }
        */

    }

    //通过sha1链接转存文件
    //uploadSetting:{targetCid,text,rootFolder:{needToCreate:true,folderName:""},itemNameSeparator:{needToSeparate:true,separator:""}}
    async function UploadFilesBySha1Links(config, continuedTaskSetting = null) {

        let uploadConfig = continuedTaskSetting == null ? config : continuedTaskSetting.uploadConfig;
        let folderSleepTime = uploadConfig.folderSetting.sleepTime;
        let nameSeparator = "";
        let newTargetCid = '-1';
        let files;
        let fileName = '';

        if (continuedTaskSetting == null) {
            //fix: v3.4 在线获取内容可能有空格,修复解析出错
            let formatedText = uploadConfig.text.trim();
            if (!formatedText) return;
            postSha1Messgae(createMessage(MessageType.BEGIN4UPLOAD, "正在解析sha1链接..."));

            //解析json，转为inline text;并且从json中获取root folder name
            if (formatedText.startsWith('{') && formatedText.endsWith('}')) {
                let r = formatJsonToCommon(formatedText);
                if (r.state) {
                    uploadConfig.folderSetting.rootFolder.folderName = r.rootFolder;
                    formatedText = r.text;
                } else {
                    console.error("json 解析失败");
                    postSha1Messgae(createMessage(MessageType.END4UPLOAD, "json解析失败！是不是格式不匹配！"));
                    return;
                    //json 解析失败，提示，，
                }
            }

            //解析inline text sha1 links,并根据配置设置分隔符

            if (uploadConfig.itemNameSeparator.needToSeparate && uploadConfig.itemNameSeparator.separator) {
                nameSeparator = uploadConfig.itemNameSeparator.separator;
            }

            files = parseSha1LinksToFileArray(formatedText, nameSeparator, errorMsg => {
                postSha1Messgae(createMessage(MessageType.ERROR, errorMsg));
            });

            if (files.length == 0) {
                postSha1Messgae(createMessage(MessageType.END, `未获取到有效的链接！`));
                return;
            }

            postSha1Messgae(createMessage(MessageType.PROCESSING, `获取到链接个数：${files.length}`));
            await delay(500);

            //根目录设置
            //根据配置重新设置targetCid
            newTargetCid = uploadConfig.targetCid;

            if (uploadConfig.folderSetting.rootFolder.needToCreate === true) {
                let rootFolderName = uploadConfig.folderSetting.rootFolder.folderName;
                let root = await createRootFolder(newTargetCid, rootFolderName, 11, folderSleepTime * 2, msg => {
                    postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
                });

                fileName = root.folderName;
                newTargetCid = root.cid;
                await delay(500);
            }
            console.log(`newTargetCid: ${newTargetCid}`);

            if (newTargetCid == "-1") {
                console.log("选择的保存处文件夹已经被删除或者移动");
                postSha1Messgae(createMessage(MessageType.END, "自动创建根目录出错：                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   <br/>选择的保存处文件夹,已经被删除或者移动，请重新选择保存位置！"));
                return;
            }

            //子目录设置
            files.forEach(f => {
                f.parentID = newTargetCid;
            });

            if (uploadConfig.folderSetting.notCreateAnyChildFolder === false) //可以创建目录
            {
                console.log("需要创建子目录");
                //根据配置设置每个文件的parent id
                //最大的层次
                let maxLevel = Math.max.apply(Math, files.map(e => e.length));
                let level = 0;
                //cid更新
                postSha1Messgae(createMessage(MessageType.PROCESSING, `正在配置子目录的生成...`));
                await updateParentID(newTargetCid, '',
                    level, maxLevel, files, folderSleepTime * 1.5, t => {
                        let st = t.state ? "成功." : "失败！！！ " + t.error;
                        let msg = `创建子目录 <b>${t.folderName}</b> ${st}`;
                        postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
                        if (!t.state) postSha1Messgae(createMessage(MessageType.ERROR, msg));
                    });


            }
        } else {
            newTargetCid = continuedTaskSetting.targetCid;
            files = continuedTaskSetting.data;
            fileName = continuedTaskSetting.fileName;
        }

        window.parent.document.myData = files;
        postSha1Messgae(createMessage(MessageType.SHOWCANCEl));
        console.log(files.length);
        //文件上传
        let hasFatalError= await processUpload(files, uploadConfig.upload.workingNumber, uploadConfig.upload.sleepTime, result => {
            if (result.state === true) {
                postSha1Messgae(createMessage(MessageType.PROCESSING, result.msg));
            } else {
                postSha1Messgae(createMessage(MessageType.ERROR, result.msg));
            }
        });

        if(hasFatalError){
            let msg=`频繁请求，被115限制 (尝试停止操作半小时或者重新登录)<br>\
            获取最新版，或者遇到问题去此反馈，感谢 !点击-> <a href="${TIPS.UpdateUrl}" target="_blank">${TIPS.VersionTips}</a>`;
            postSha1Messgae(createMessage(MessageType.FATALERRORUPLOAD, msg, newTargetCid));
            return;
        }
        

        

        let isTaskCanceled = getTaskCancelFlag();

        postSha1Messgae(createMessage(MessageType.HIDECANCEL));

        //根据配置，重命名文件
        if (uploadConfig.itemNameSeparator.needToSeparate &&
            uploadConfig.itemNameSeparator.needToRemoveSeparator &&
            uploadConfig.itemNameSeparator.separator &&
            !isTaskCanceled) {
            postSha1Messgae(createMessage(MessageType.PROCESSING, "开始获取文件，并自动重命名..."));
            await delay(folderSleepTime);
            console.log(files)
            await processRenameByUsingHistory(files, uploadConfig.itemNameSeparator.separator, folderSleepTime, result => {
                if (result.state === true) {
                    postSha1Messgae(createMessage(MessageType.PROCESSING, result.msg));
                } else {
                    postSha1Messgae(createMessage(MessageType.ERROR, result.msg));
                }
            });
            // await processRename(newTargetCid, uploadConfig.itemNameSeparator.separator, folderSleepTime, result => {
            //     if (result.state === true) {
            //         postSha1Messgae(createMessage(MessageType.PROCESSING, result.msg));
            //     } else {
            //         postSha1Messgae(createMessage(MessageType.ERROR, result.msg));
            //     }
            // });

            postSha1Messgae(createMessage(MessageType.PROCESSING, "文件批量去除分隔符（重命名）完成！"));
            await delay(folderSleepTime * 2);
        }

        var fails = files.filter(q => !q.state);
        var failText = fails.map(function (p) {
            var r = convertToSha1Link(p, false);
            return r.msg;
        }).join("\r\n");

        if (failText) GM_setClipboard(failText);
        if (isTaskCanceled) {
            //todo:取消转存
            let file_name = fileName + "_转存_未完成.7task";
            let data = files.map(f => {
                `let tempFile={
                            parentID:f.parentID,
                            name:f.name,
                            size:f.size,
                            sha1:f.sha1,
                            preid:f.preid,
                        };`
                let tempFile = [
                    f.parentID, f.name, f.formatedName, f.size, f.sha1, f.preid, f.state
                ];
                return tempFile;
            });
            uploadConfig.text = '';
            let taskJson = {
                taskType: TaskType.UPLOAD,
                targetCid: newTargetCid,
                fileName: fileName,
                data: data,
                uploadConfig: uploadConfig
            };
            let text = JSON.stringify(taskJson)
            download(file_name, text);

        }

        let msg = `完成上传！成功 <b>${(files.length - fails.length)}</b> ，失败或者取消 <b>${fails.length}</b>\
                <br><br>如果有失败，已将失败sha1链接复制到剪贴板！如果转存失败，请检查sha1链接格式或者在 chrome 上尝试转存。\
                获取最新版，或者遇到问题去此反馈，感谢 !点击-> <a href="${TIPS.UpdateUrl}" target="_blank">${TIPS.VersionTips}</a>`;
        postSha1Messgae(createMessage(MessageType.END4UPLOAD, msg, newTargetCid));

    }



    function getFileItemPreidWithTimeOut(timeOut, file) {
        console.log('getFileItemPreidWithTimeOut')
        let to = delay(timeOut).then(t => {
            return {
                state: false,
                error: `等待提取结果超时，此乃警告，成功与否看最后结果！`,
                fileItem: file
            }
        });
        let up = getFileItemPreid(file);

        return Promise.race([to, up]);
    }


    function GetFileItemByliNode(liNode) {

        var pItem = {
            id: "",
            parentID: "",
            isFolder: false,
            name: "",
            size: 0,
            pickCode: "",
            sha1: "",
            paths: [],
            preid: "",
            selected: false

        };

        var type = liNode.getAttribute("file_type");
        pItem.name = liNode.getAttribute('title');
        pItem.parentID = liNode.getAttribute('p_id');

        var isSelected = liNode.getAttribute('class');
        if (isSelected == "selected") pItem.selected = true;

        if (type == "0") {
            pItem.id = liNode.getAttribute('cate_id');
            pItem.isFolder = true;
        } else {
            pItem.size = liNode.getAttribute('file_size');
            pItem.sha1 = liNode.getAttribute('sha1');
            pItem.pickCode = liNode.getAttribute('pick_code');
            pItem.id = liNode.getAttribute('file_id');
        }

        return pItem;
    }

    const FILESIZE = 128 * 1024;
    async function InnerCreateSha1Links(allFiles, txtName) {
        var msg = "";
        var index = 1;
        var completedIndex = 1;
        var promisArray = new Array();

        for (let file of allFiles) {
            let fileSize = parseInt(file.size);
            file.size = fileSize;
            if (!file.preid && file.size <= FILESIZE) {
                file.preid = file.sha1;
            }
        }

        let files = allFiles.filter(f => !f.preid);
        completedIndex = allFiles.length - files.length;
        var gt1200files = files.length >= 1200;
        console.log(`>=1200: ${gt1200files}`);
        //postSha1Messgae(createMessage(MessageType.PROCESSING, `总计${allFiles.length},已完成${completedIndex}`));
        postSha1Messgae(createMessage(MessageType.SHOWCANCEl))
        for (var file of files) {


            let taskCancelFlag = getTaskCancelFlag();
            console.log(taskCancelFlag);
            if (taskCancelFlag === true) {
                console.log("InnerCreateSha1Links has Canceled");
                break;
            }

            const f = file;

            // getFileItemPreid
            const r = getFileItemPreidWithTimeOut(20000, f).then((t) => {
                if (t.state) {
                    msg = '<div align="right"><b>{0}</b> | <b>{1}</b></div><hr>获取【 <b>{2}</b> 】的sha1链接成功'.format(completedIndex, allFiles.length, t.fileItem.name);
                    postSha1Messgae(createMessage(MessageType.PROCESSING, msg))
                } else {
                    msg = '<div align="right"><b>{0}</b> | <b>{1}</b></div><hr>获取【 <b>{2}</b> 】的sha1链接：{3}'.format(completedIndex, allFiles.length, t.fileItem.name, t.error);
                    postSha1Messgae(createMessage(MessageType.PROCESSING, msg))
                    var filePath = t.fileItem.paths.join(" > ");
                    console.log(filePath);
                    if (filePath) msg = "{0},原因：{1},路径：{2}".format(t.fileItem.name, t.error, filePath);
                    else msg = "{0},原因：{1}".format(t.fileItem.name, t.error);

                    postSha1Messgae(createMessage(MessageType.ERROR, msg));
                }
                completedIndex = completedIndex + 1;
            });

            promisArray.push(r);

            //自己改代码吧，怎么弄提取逻辑。。太慢，耗时长；太快，115容易没反应
            if (index % WORKSETTINGS.WorkingItemsNumber == 0) {
                await delay(WORKSETTINGS.SleepMoreTime * 1.5);
                if (index % (WORKSETTINGS.WorkingItemsNumber * 9) == 0) {
                    await Promise.all(promisArray);
                    let seconds = 2;
                    for (let i = 0; i < seconds; i++) {
                        postSha1Messgae(createMessage(MessageType.PROCESSING, `防止115服务器限制，暂停发包中。<br><br>${seconds - i}秒后继续...`));
                        await delay(1000);
                    }
                    promisArray = new Array();
                }
            }

            //
            index = index + 1;
        }


        await Promise.all(promisArray);

        var succeedArray = allFiles.filter(q => q.preid);
        if (succeedArray.length == 1) {
            var result = convertToSha1Link(succeedArray[0], false);
            postSha1Messgae(createMessage(MessageType.CLOSE, ""));

            setTimeout(s => {
                prompt("复制分享链接到剪贴板", s);
            }, 100, result.msg);

        } else {


            if (succeedArray.length > 1) {

                let file_name = txtName + "_sha1.txt";
                let text = "";


                if (getTaskCancelFlag()) {
                    file_name = txtName + "_提取_未完成.7task";
                    let data = allFiles.map(f => {
                        `let tempFile={
                            id:f.id,
                            parentID:f.parentID,
                            name:f.name,
                            size:f.size,
                            paths:f.paths,
                            pickCode:f.pickCode,
                            sha1:f.sha1,
                            preid:f.preid,
                        };`
                        let tempFile = [
                            f.id, f.parentID, f.name, f.size, f.paths, f.pickCode, f.sha1, f.preid,
                        ];
                        return tempFile;
                    });
                    let taskJson = {
                        taskType: TaskType.DOWNLOAD,
                        fileName: txtName,
                        data: data
                    };
                    text = JSON.stringify(taskJson)
                    //todo:取消任务

                } else {
                    text = allFiles.filter(q => q.preid).map(function (p) {
                        var r = convertToSha1Link(p, false);
                        return r.msg;
                    }).join("\r\n");
                }
                download(file_name, text);
            }



            msg = `
            完成【 <b>${txtName}</b> 】提取！<hr><br>
            总共<b>${allFiles.length}</b> ，取消或者失败 <b>${allFiles.length - succeedArray.length}</b>。<br>
            取消后，若未移动文件夹，可导入继续提取。<br>
            点击-> <a href="${TIPS.UpdateUrl}" target="_blank">${TIPS.VersionTips}</a>，获取最新版与反馈！
            `;
            console.log(msg);
            postSha1Messgae(createMessage(MessageType.END, msg));
        }
    }

    async function CreateSha1LinksAll(items, taskName) {
        //ui: 获取文件中...
        var msg = "正在获取文件...";
        postSha1Messgae(createMessage(MessageType.BEGIN, msg));
        var files = new Array();
        for (let item of items) {
            if (getTaskCancelFlag()) break;

            if (!item.isFolder) {
                files.push(item);
            } else {
                msg = `正在获取 ${item.name} 下的内容...`;
                postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
                let children = new Array();
                await getAllFiles(item.id, children, item.id, (fname, pIndex) => {
                    if (pIndex > 1) {
                        msg = `正在获取 【${fname}】 下第 ${pIndex} 页的内容...`;
                    } else {
                        msg = `正在获取 【${fname}】 下的内容...`;
                    }
                    postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
                });

                for (let f of children) {
                    f.paths.unshift(item.name);
                    files.push(f);
                }


            }
        }

        if (!files || files.length == 0) {
            postSha1Messgae(createMessage(MessageType.END, `未选中任何内容???`));
            return;
        }

        postSha1Messgae(createMessage(MessageType.PROCESSING, `获取到 【<b>${taskName}</b>】 的内容 ${files.length} 项`));
        await delay(100);
        if (getTaskCancelFlag()) {
            postSha1Messgae(createMessage(MessageType.END, "已经取消任务！"));
        } else InnerCreateSha1Links(files, taskName);
    }


    async function CreateSha1Links(item) {
        //ui: 获取文件中...
        var msg = "正在获取文件...";
        postSha1Messgae(createMessage(MessageType.BEGIN, msg));
        var files = new Array();

        if (!item.isFolder) {
            files.push(item);
        } else {
            msg = `正在获取 ${item.name} 下的内容...`;
            postSha1Messgae(createMessage(MessageType.PROCESSING, msg));

            await getAllFiles(item.id, files, item.id, (fname, pIndex) => {
                if (pIndex > 1) {
                    msg = "正在获取 【{0}】 下第 {1} 页的内容...".format(fname, pIndex);
                } else {
                    msg = "正在获取 【{0}】 下的内容...".format(fname);
                }
                postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
            });

            if (!files || files.length == 0) {
                postSha1Messgae(createMessage(MessageType.END, "【<b>{0}</b> 】空目录???".format(item.name)));
                return;
            }
        }

        postSha1Messgae(createMessage(MessageType.PROCESSING, "获取到 【<b>{0}</b>】 的内容 {1} 项".format(item.name, files.length)));
        await delay(100);
        if (getTaskCancelFlag()) {
            postSha1Messgae(createMessage(MessageType.END, "已经取消任务！"));
        } else InnerCreateSha1Links(files, item.name);
    }

    const autoCreateRootFolderTips = {
        msg: `sha1转存时，强制在保存处新建根目录`,
        details: `选择时:&#013;&#010;1.新建根目录名来自sha1转存文件名或者json中的根元素。\
        &#013;&#010;2.如果没有,则当前时间为文件名生成。`
    };

    const autoCreateRootFolderString =
        `<div class="linktask-quota" style="height: 40px;display: block">\
        <a>${autoCreateRootFolderTips.msg}</a>\
        <div class="help" title=" ${autoCreateRootFolderTips.details}"><a></a></div>\
        <span>&nbsp;&nbsp;</span><div class="option-switch" style="top:10px;left:10px">\
        <input type="checkbox" checked="true" id="neAutoCreateRootfolder" onclick="function f() {return false}">\
        <label for><i>开启</i><s>关闭</s><b>切换</b></label></div>`;

    const notCreateAnyChildFolderTips = {
        msg: `sha1转存时，不创建任何子目录`,
        details: `选中时，不会自动创建任何子目录。此项与根目录不会影响！`
    };

    const notCreateAnyChildFolderString =
        `<div id="neNotCreateAnyChildFolderParent" class="linktask-quota" style="height: 40px;display: block">\
        <a>${notCreateAnyChildFolderTips.msg}</a>\
        <div class="help" title=" ${notCreateAnyChildFolderTips.details}"><a></a></div>\
        <span>&nbsp;&nbsp;</span><div class="option-switch" style="top:10px;left:10px">\
        <input type="checkbox" checked="true" id="neNotCreateAnyChildFolder" onclick="function f() {return false}">\
        <label for><i>开启</i><s>关闭</s><b>切换</b></label></div>`;

    const selectFileTips = {
        msg: `或者导入sha1链接文件（txt/json）`,
        details: `如果不能正确显示选择文件按钮，可能是与其他脚本或者插件冲突！！`
    };
    const selectFileString = `<div id="neFile">
    <div id="neFileOnline">
    <span style="display:flex;margin-top: 10px;">已经选择在线文件:<p style="color:red" id="neOnlineFileName"></p></span>
    </div>
    <div id="neFileUpload" >
    <div class="linktask-quota" style="margin-top: 10px;">\
        <a>${selectFileTips.msg}</a>\
        <div class="help" title="${selectFileTips.details}"><a></a></div>\
        <span>&nbsp;&nbsp;</span><input type="file" id="neSelectFile" accept=".txt,.json" style="display:block;color:#2777F8;visibility: visible;"></input></div>
    </div>
    </div>`;

    const otherSettingString = `<div class="linktask-quota" style="margin-top: 10px;display:none;">\
        分隔符或者其他选项：<a id="neSetting1" href="javascript:;" style="color:#2777F8">点此设置</a>。\
        </div>`


    const headerString = `<div id="ne115tipsforheader">${TIPS.VersionTips}(${TIPS.LastUpdateDate}),\
    <a style="color:red;" target="_blank" href=${TIPS.UpdateUrl}>更新&反馈点此!</a>\
    <a href="javascript:;" style="color:#2777F8" id="neSetting2">分隔符等设置点此！</a></div>`;

    const beginUploadBySha1String = `<div class="con" id="downsha1"><a class="button" href="javascript:;">开始sha1转存</a></div>`;

    //当前页面所在的目录信息
    function getCurrentFolderDisplayed() {
        let defaultFolder = {
            id: "0",
            name: "根目录"
        };
        let iframes = document.querySelectorAll('iframe')
        for (let item of iframes) {
            let filePath = item.contentWindow.document.body.querySelector('[rel=header_page_local]');
            if (filePath) {
                let folders = filePath.querySelectorAll('.folder');
                let lastFolder = folders[folders.length - 1];
                defaultFolder.name = lastFolder.getAttribute('titletext');
                let search = new URLSearchParams(window.location.search);
                defaultFolder.id = search.get('cid');
                break;
            }
        }

        return defaultFolder;
    }

    //fix: v3.3 修复“添加任务弹窗可能无法关闭”
    function AddDownloadSha1Btn(jNode) {

        document.querySelector(`a[btn="close"]`).addEventListener('click', e => {
            window.parent.document.tryUploadItem = null;
        });



        let onlineFile = null;

        var file = "";

        var dialog = document.getElementsByClassName("dialog-box dialog-mini offline-box window-current")[0];
        dialog.style.width = "720px";
        dialog.style.top = "10px";
        if (document.getElementById('ne115tipsforheader') == null) {
            $(headerString).appendTo(".dialog-header[rel$='title_box']");

            $('#neSetting2')[0].addEventListener('click', e => {
                document.querySelector(`a[btn="close"]`).click();
                GM_config.open();
            });
        }

        var textArea = document.querySelector("#js_offline_new_add");
        if (textArea) {
            textArea.style.height = "100px";
        }

        if (document.getElementById('neSelectFile') == null) {
            var div = document.getElementsByClassName('dialog-input input-offline');

            console.log(div);
            var $selectFile = $(selectFileString);
            var $autoCreateRootFolder = $(autoCreateRootFolderString);
            var $notCreateAnyChildFolder = $(notCreateAnyChildFolderString);
            var $otherSetting = $(otherSettingString);
            div[0].style.display = 'grid';
            div[0].appendChild($selectFile[0]);
            div[0].appendChild($autoCreateRootFolder[0]);

            div[0].appendChild($notCreateAnyChildFolder[0]);
            div[0].appendChild($otherSetting[0]);


            //界面选项设置
            //根目录自动创建默认值：
            document.getElementById('neAutoCreateRootfolder').checked = GM_config.get(currentConfig.createRootFolderDefaultValue);
            //是否显示不创建任何目录：
            document.getElementById('neNotCreateAnyChildFolderParent').style.display = GM_config.get(currentConfig.createChildFolderVisible) === true ? 'block' : 'none';
            document.getElementById('neNotCreateAnyChildFolder').checked = false;

            $selectFile[0].addEventListener('change', e => {
                console.log(e.target.files);
                if (e.target.files) {
                    file = e.target.files[0];
                } else {
                    file = "";
                }
            });

            $('#neSetting1')[0].addEventListener('click', e => {
                document.querySelector(`a[btn="close"]`).click();
                GM_config.open();
            });


        } else {

            //界面选项设置
            document.getElementById('neSelectFile').value = "";
            file = "";
            //根目录自动创建默认值：
            document.getElementById('neAutoCreateRootfolder').checked = GM_config.get(currentConfig.createRootFolderDefaultValue);
            //是否显示不创建任何目录：
            document.getElementById('neNotCreateAnyChildFolderParent').style.display = GM_config.get(currentConfig.createChildFolderVisible) === true ? 'block' : 'none';
            document.getElementById('neNotCreateAnyChildFolder').checked = false;
        }


        if (document.getElementById('downsha1') == null) {

            resetTaskCancelFlag();

            var $btn = $(beginUploadBySha1String);
            jNode[0].appendChild($btn[0]);
            $btn[0].addEventListener('click', e => {

                let cid = $(`li[rel="bts_select_item"][class="selected"]`).attr("file_id");
                if (cid == "") {
                    //目录不存在，比如把 “云下载” 目录删除
                    cid = '0';
                }

                let notCreateAnyChildFolder = document.getElementById('neNotCreateAnyChildFolder').checked;
                let autoCreateRootfolder = document.getElementById('neAutoCreateRootfolder').checked;

                let links = document.getElementById('js_offline_new_add').value;
                let config = {
                    targetCid: cid,
                    text: "",
                    folderSetting: {
                        notCreateAnyChildFolder: notCreateAnyChildFolder,
                        sleepTime: GM_config.get(currentConfig.createFolderSleepTime),
                        rootFolder: {
                            needToCreate: autoCreateRootfolder,
                            folderName: ""
                        },
                    },
                    itemNameSeparator: {
                        needToSeparate: GM_config.get(currentConfig.autoUseSeparator),
                        needToRemoveSeparator: GM_config.get(currentConfig.autoUseSeparatorToRename),
                        separator: GM_config.get(currentConfig.separator)
                    },
                    upload: {
                        workingNumber: GM_config.get(currentConfig.uploadNumber),
                        sleepTime: GM_config.get(currentConfig.uploadSleepTime),
                    }
                };


                onlineFile = window.parent.document.tryUploadItem
                if (onlineFile) {
                    document.querySelector(`a[btn="close"]`).click();
                    console.log("选择了在线文件：")
                    config.folderSetting.rootFolder.folderName = onlineFile.name.split(".").slice(0, -1).join('.');

                    postSha1Messgae(createMessage(MessageType.FILEDOWNLOAD, {
                        onlineFile: onlineFile,
                        config: config
                    }));
                    window.parent.document.tryUploadItem = null;

                } else if (file) {
                    console.log("选择了文件：")
                    console.log(file);
                    let reader = new FileReader();
                    reader.addEventListener('load', function (t) {
                        //fix: v3.3 导入的文件名带"."
                        config.folderSetting.rootFolder.folderName = file.name.split(".").slice(0, -1).join('.');
                        config.text = t.target.result;
                        file = "";
                        UploadFilesBySha1Links(config);
                    });
                    reader.readAsText(file);
                    document.querySelector(`a[btn="close"]`).click();
                    //(document.getElementsByClassName('close')[2].click());

                } else if (links) {

                    console.log("选择了文本框中输入：")
                    // var text = { FileName: "", Content: links };
                    config.folderSetting.rootFolder.folderName = "";
                    config.text = links;

                    document.querySelector(`a[btn="close"]`).click();
                    //closeButton.click();
                    UploadFilesBySha1Links(config);



                }



            });
        }

        let save = document.querySelector('.bt-task-safe')
        if (save != null && document.querySelector('#saveTip') == null) {
            save.insertAdjacentHTML('afterend', `<div id="saveTip"><p style="margin-left:20px;margin-top:-20px;">转存也在此处选择位置。<span style="color:red;">因115页面结构以及接口调整，暂时下线【默认保存至当前位置】</span></p></div>`)
        }


        if (window.parent.document.tryUploadItem) {
            document.getElementById('neFileOnline').style.display = "block";
            document.getElementById('neFileUpload').style.display = "none";
            document.getElementById('neOnlineFileName').innerText = window.parent.document.tryUploadItem.name;
        } else {
            document.getElementById('neFileOnline').style.display = "none";
            document.getElementById('neFileUpload').style.display = "block";
        }

        let currentFolder = getCurrentFolderDisplayed();
        console.log(currentFolder);

        /*
                let ul = document.querySelector('ul[rel="select_item_ul"]');
        if (ul) {
            //弹窗时可能数据还在获取，延迟修改
            //fix: v3.3.1 优化”脚本修改比自带的快“
            //fix: v3.4 再次延长，优化”脚本修改比自带的快“
            delay(1000).then(t => {
                const lis = ul.querySelectorAll("li");
                let folderIncluded = null;

                for (const li of lis) {
                
                    if(li.className&&li.className.includes("selected"))
                    {
                        li.classList.remove("selected")
                    }

                    console.log(li.attributes['file_id'])
                    if (li.attributes['file_id'].value == currentFolder.id) {
                        folderIncluded = li;
                    }
                };
                
                console.log(folderIncluded)
                if(folderIncluded){
                    folderIncluded.classList.add("selected");
                }
                else{
                    const li = `<li rel="bts_select_item" class="selected" file_id="${currentFolder.id}"><a href="javascript:;"><span>${currentFolder.name}</span></a></li>`;
                    ul.insertAdjacentHTML("afterbegin", li);
                }

                

                const em= document.querySelector('em[rel="downFileResult"]');
                if(em){
                    em.textContent=currentFolder.name;
                }
            });

        }
        */






    }


    // function formatCommonToJson(children, root) {
    //     let childFiles = children.filter(f => f.Paths.length == 0);
    //     root.files = Array();
    //     root.dirs = Array();
    //     childFiles.forEach(c => root.files.push({ Name: c.Name }));

    //     let selectedChildren = children.filter(f => f.Paths.length > 0);

    //     let childFolders = selectedChildren.map(q => q.Paths[0]).filter((v, i, a) => a.indexOf(v) === i);
    //     childFolders.forEach(f => root.dirs.push({ dir_name: f }));

    //     root.dirs.forEach(d => {
    //         let newChildren = selectedChildren.filter(f => f.Paths[0] == d.dir_name)
    //             .map(c => {
    //                 let a = { Name: c.Name, Paths: c.Paths.slice(1) };
    //                 return a;
    //             })
    //         ConverterAdvanced(newChildren, d);
    //     });
    // }



    function AddCeateSha1ButtonInGrid(jNode) {
        //add: v3.4 增加设置是否显示 缩略图模式下获取sha1
        if (!GM_config.get(currentConfig.createItemSha1InThumb)) return;
        let $li = jNode.find('[class~="file-thumb"]');
        //fix: v3.3.1 修正文件夹如果设置封面，获取sha1链接按钮会覆盖的bug
        let $button = $('<button class="btnInGrid" title="获取sha1链接"><i class="icon-operate-light ifol-download" style="height:14px;width:14px;position:inherit"></i></button>');
        $button.appendTo($li);
        $button.click(function (e) {
            e.stopPropagation();
            let pItem = GetFileItemByliNode(jNode[0]);
            console.log("生成sha1");
            console.log(pItem);
            //生成sha1
            resetTaskCancelFlag();
            CreateSha1Links(pItem);
        });

    }


    function renameInToolTip(element, pItem) {
        var $btn1 = $('<a><i></i><span>遍历文件夹</span></a>');
        $btn1.prependTo(element);
        $btn1[0].addEventListener('click', async e => {
            let separator = GM_config.get(currentConfig.separator);
            let sleepTime = GM_config.get(currentConfig.createFolderSleepTime);
            postSha1Messgae(createMessage(MessageType.BEGIN4UPLOAD, ""));
            postSha1Messgae(createMessage(MessageType.PROCESSING, `即将开始遍历 【${pItem.name}】 下所有文件：<br>`));
            await delay(1000);
            await processRename(pItem.id, separator, sleepTime, result => {
                if (result.state === true) {
                    postSha1Messgae(createMessage(MessageType.PROCESSING, result.msg));
                } else {
                    postSha1Messgae(createMessage(MessageType.ERROR, result.msg));
                }
            });

            postSha1Messgae(createMessage(MessageType.END4UPLOAD, `对目录 【${pItem.name}】下的文件重命名完成！\
                <br><br>获取最新版，或者遇到问题去此反馈，感谢 !点击->\
                <a href="${TIPS.UpdateUrl}" target="_blank">${TIPS.VersionTips}</a>`, pItem.id));
        })
    }

    function createSha1InToolTip(toopTip, pItem) {
        var $btn = $('<a ><i></i><div style="background:white"><span>获取SHA1链接</span></div></a>');

        $btn.prependTo(toopTip);
        $btn[0].addEventListener('click', e => {
            console.log("生成sha1");
            console.log(pItem);
            //生成sha1
            resetTaskCancelFlag();
            CreateSha1Links(pItem);
        })
    }

    function usingOnlineFileToUploadInToolTip(toopTip, pItem) {

        let temps = pItem.name.split('.');
        let extension = temps[temps.length - 1].toLowerCase();
        if (extension == "json" || extension == "txt") {
            let $btn1 = $('<a menu="offline_task" title="暂不支持大于2MB的文本文件操作"><i></i><div style="background:white"><span>尝试转存</span></div></a>');
            $btn1.prependTo(toopTip);
            //尝试转存
            $btn1[0].addEventListener('click', e => {
                window.parent.document.tryUploadItem = pItem;
            })
        }
    }

    //fix:v3.3 修复在回收站显示提取的bug
    function AddShareSHA1Btn(jNode) {

        var parentNode = jNode[0].parentNode;
        var pItem = GetFileItemByliNode(parentNode);
        if (!pItem.name) return;


        jNode[0].style.left = "180px";
        //目录，去除分隔符
        if (pItem.isFolder && GM_config.get(currentConfig.advancedRename)) {
            renameInToolTip(jNode[0], pItem);
        }

        //add: v3.4 增加设置是否显示 列表模式下获取sha1
        if (GM_config.get(currentConfig.createItemSha1)) {
            createSha1InToolTip(jNode[0], pItem);
        }


        if (!pItem.isFolder) {
            usingOnlineFileToUploadInToolTip(jNode[0], pItem);
        }



        //生成json格式
        // if(pItem.isFolder)
        // {
        //     var $btn1 = $('<a><i></i><span>获取SHA1(json)</span></a>');
        //     $btn1.prependTo(jNode[0]);
        //     $btn1[0].addEventListener('click', e => {
        //         console.log(pItem);
        //     //生成sha1
        //         resetTaskCancelFlag();
        //         CreateSha1Links(pItem);
        //     })
        // }


    }

    async function GetSearchList(isOnlySelected) {
        resetTaskCancelFlag();

        var msg = "正在获取文件...";
        postSha1Messgae(createMessage(MessageType.BEGIN, msg));

        var doc = document.getElementsByClassName('search-iframe')[0];
        if (!doc) doc = document;
        var lis = doc.querySelectorAll('.list-cell.lstc-search > .list-contents > ul > li');
        if (!lis) return;
        console.log(lis);
        var files = new Array();
        for (var li of lis) {
            var fileItem = GetFileItemByliNode(li);
            files.push(fileItem);
        }
        console.log("0: search items{0}".format(files.length));
        if (isOnlySelected) {
            console.log("search items onlySelected")
            files = files.filter(q => q.selected);
        }

        console.log("1: search items{0}".format(files.length));

        console.log(document.URL);
        var url = new URL(document.URL);
        var key = url.searchParams.get("search_value");
        key = key ? key : "搜索结果";
        files = files.filter(q => !q.isFolder);
        msg = "获取到符合搜索的文件数：{0}".format(files.length);
        postSha1Messgae(createMessage(MessageType.PROCESSING, msg));
        await delay(200);
        await InnerCreateSha1Links(files, key)

    }

    function CreateSha1ButtonForSelectedItems(element) {
        if (document.getElementById('my115CreateSha1ForSelected')) return;

        let div = `<div id="my115CreateSha1ForSelected" style="margin-left:20px;cursor:pointer">
        <a hef="javascript=:;" class="button btn-line">
        <i class="icon-operate ifo-share"></i>
        <span>获取选中项的SHA1链接</span>
        </a>
      </div>`
        element[0].insertAdjacentHTML('beforeend', div);
        document.getElementById('my115CreateSha1ForSelected').addEventListener('mousedown', async e => {
            e.stopPropagation();
            let seletedElements = new Array();
            //列表模式下：
            let selectedItemsInList = document.querySelectorAll('.list-contents > ul > li')
            console.log(`列表模式下,选中:${selectedItemsInList.length}`);
            selectedItemsInList.forEach(ele => seletedElements.push(ele));
            //缩略图模式下：
            selectedItemsInList = document.querySelectorAll('.list-thumb > ul > li')
            console.log(`缩略图模式下,选中:${selectedItemsInList.length}`);
            selectedItemsInList.forEach(ele => seletedElements.push(ele));

            console.log(`选中:${seletedElements.length}`);
            let items = new Array();
            for (let item of seletedElements) {
                let sItem = GetFileItemByliNode(item);
                if (sItem.selected) items.push(sItem);
            }

            if (items.length == 0) return;
            if (items.length == 1) {
                await CreateSha1Links(items[0])
            } else {
                await CreateSha1LinksAll(items, `${items[0].name}等${items.length}个`)
            }

        });


    }



    function AddShareButtonForSearchItem(node) {

        document.getElementById('my115Dropdown').style.display = 'none';

        //每一项
        var lis = node[0].getElementsByTagName('li');
        for (var li of lis) {
            var pItem = GetFileItemByliNode(li);
            var $btn = $('<div class="file-opr" style="left:200px"></div>');
            $btn.appendTo(li);
        }

        //针对当前页面
        $(".left-tvf > a.btn-upload").css("top", "10px");
        if (document.getElementById('btn_selected_sha1') == null) {
            var $btn_selected = $(`<a href="javascript:;" id="btn_selected_sha1" class="button btn-line" style="top:10px">
            <i class="icon-operate ifo-share"></i>
            <span>提取本页选中文件（不包括文件夹）</span>
            <em style="display:none;" class="num-dot"></em>
            </a>`);
            $(".left-tvf").eq(0).append($btn_selected);

            $btn_selected[0].addEventListener('click', e => {
                GetSearchList(true);
            });
        }

        if (document.getElementById('btn_all_sha1') == null) {
            var $btn_all = $(`<a href="javascript:;" id="btn_all_sha1" class="button btn-line" style="top:10px">
            <i class="icon-operate ifo-share"></i>
            <span>提取本页所有文件（不包括文件夹）</span>
            <em style="display:none;" class="num-dot"></em>
            </a>`);
            $(".left-tvf").eq(0).append($btn_all);

            $btn_all[0].addEventListener('click', e => {
                GetSearchList(false);
            });
        }


    }



    function ContinuedTask(taskJsonFileName) {
        console.log("ContinuedTask");
        postSha1Messgae(createMessage(MessageType.BEGIN, "正在继续任务..."));
        resetTaskCancelFlag();
        let reader = new FileReader();
        reader.addEventListener('load', function (t) {
            try {

                postSha1Messgae(createMessage(MessageType.PROCESSING, "正在解析继续任务配置..."));
                let taskJson = JSON.parse(t.target.result);

                console.log(`${taskJson.taskType}, ${taskJson.fileName}, ${taskJson.data.length}`);
                let canContinued = true;
                if (taskJson.data.length > 0) {

                } else {
                    canContinued = false;
                }
                if (canContinued) {
                    if (taskJson.taskType == TaskType.DOWNLOAD) {
                        postSha1Messgae(createMessage(MessageType.PROCESSING, `正在开始对【${taskJson.fileName}】继续提取...请稍等！`));
                        `
                        提取：
                            let tempFile=[
                            f.id,f.parentID,f.name,f.size,f.paths,f.pickCode,f.sha1,f.preid,
                            ];
                        `
                        let allFiles = taskJson.data.map(f => {
                            return {
                                id: f[0],
                                parentID: f[1],
                                name: f[2],
                                size: f[3],
                                paths: f[4],
                                pickCode: f[5],
                                sha1: f[6],
                                preid: f[7],
                            }
                        });
                        InnerCreateSha1Links(allFiles, taskJson.fileName);
                    } else if (taskJson.taskType == TaskType.UPLOAD) {
                        postSha1Messgae(createMessage(MessageType.BEGIN4UPLOAD, "正在解析sha1链接..."));
                        `转化格式
                        转存：
                        let tempFile = [
                            f.parentID,f.name, f.formatedName, f.size, f.sha1, f.preid,f.state
                        ]
                        `
                        let allFiles = taskJson.data.map(f => {
                            return {
                                id: '',
                                parentID: f[0],
                                name: f[1],
                                formatedName: f[2],
                                size: f[3],
                                pickCode: '',
                                sha1: f[4],
                                preid: f[5],
                                state: f[6]
                            }
                        });

                        taskJson.data = allFiles;

                        UploadFilesBySha1Links(null, taskJson);


                    }
                } else {
                    let msg = `
                    获取的继续任务：【 <b>${taskJson.fileName}</b> 】,配置有误！<br>
                    可能不是正确的配置文件, 或者不适用于此版本的配置！
                    `;
                    postSha1Messgae(createMessage(MessageType.END, msg));
                }


            } catch (error) {
                console.error(error);
            }

        });
        reader.readAsText(taskJsonFileName);



    }




})();
