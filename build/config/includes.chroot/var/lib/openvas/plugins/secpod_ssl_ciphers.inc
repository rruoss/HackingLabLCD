###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ssl_ciphers.inc 63 2013-11-12 13:49:07Z veerendragg $
#
# Check SSL Weak Ciphers and Supported Ciphers
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# cipher lists has been take from ssl-enum tool,
# http://code.google.com/p/ssl-enum
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

## Mapping SSLv2 Cipher codes and Display Names
sslv2_ciphers_codes = make_list
                (
                  raw_string(0x01, 0x00, 0x80),
                  raw_string(0x02, 0x00, 0x80),
                  raw_string(0x03, 0x00, 0x80),
                  raw_string(0x04, 0x00, 0x80),
                  raw_string(0x05, 0x00, 0x80),
                  raw_string(0x06, 0x00, 0x80)
                );

sslv2_ciphers_disply = make_list
                (
                  "SSL2_RC4_128_MD5 : SSL_NOT_EXP : High Cipher",
                  "SSL2_RC4_128_EXPORT40_WITH_MD5 : SSL_EXPORT : Weak Cipher",
                  "SSL2_RC2_CBC_128_CBC_WITH_MD5 : SSL_NOT_EXP : High Cipher",
                  "SSL2_RC2_CBC_128_CBC_EXPORT40_WITH_MD5 : SSL_EXPORT : Weak Cipher",
                  "SSL2_IDEA_128_CBC_WITH_MD5 : SSL_NOT_EXP : High Cipher",
                  "SSL2_UNKNOWN : UNKNOWN"
                );


## Mapping SSLv3/TLSv1 Cipher codes and Display Names
sslv3_tlsv1_ciphers_codes = make_list
                (
                  raw_string(0x00, 0x00), raw_string(0x00, 0x01), raw_string(0x00, 0x02),
                  raw_string(0x00, 0x03), raw_string(0x00, 0x04), raw_string(0x00, 0x05),
                  raw_string(0x00, 0x06), raw_string(0x00, 0x07), raw_string(0x00, 0x08),
                  raw_string(0x00, 0x09), raw_string(0x00, 0x0A), raw_string(0x00, 0x0B),
                  raw_string(0x00, 0x0C), raw_string(0x00, 0x0D), raw_string(0x00, 0x0E),
                  raw_string(0x00, 0x0F),

                  raw_string(0x00, 0x10), raw_string(0x00, 0x11), raw_string(0x00, 0x12),
                  raw_string(0x00, 0x13), raw_string(0x00, 0x14), raw_string(0x00, 0x15),
                  raw_string(0x00, 0x16), raw_string(0x00, 0x17), raw_string(0x00, 0x18),
                  raw_string(0x00, 0x19), raw_string(0x00, 0x1A), raw_string(0x00, 0x1B),
                  raw_string(0x00, 0x1C), raw_string(0x00, 0x1D), raw_string(0x00, 0x1E),
                  raw_string(0x00, 0x1E), raw_string(0x00, 0x1F),

                  raw_string(0x00, 0x20), raw_string(0x00, 0x21), raw_string(0x00, 0x22),
                  raw_string(0x00, 0x23), raw_string(0x00, 0x24), raw_string(0x00, 0x25),
                  raw_string(0x00, 0x26), raw_string(0x00, 0x27), raw_string(0x00, 0x28),
                  raw_string(0x00, 0x29), raw_string(0x00, 0x2A), raw_string(0x00, 0x2B),

                  raw_string(0x00, 0x30), raw_string(0x00, 0x31), raw_string(0x00, 0x32),
                  raw_string(0x00, 0x33), raw_string(0x00, 0x34), raw_string(0x00, 0x35),
                  raw_string(0x00, 0x36), raw_string(0x00, 0x37), raw_string(0x00, 0x38),
                  raw_string(0x00, 0x39), raw_string(0x00, 0x3A),

                  raw_string(0x00, 0x41), raw_string(0x00, 0x42), raw_string(0x00, 0x43),
                  raw_string(0x00, 0x44), raw_string(0x00, 0x45), raw_string(0x00, 0x46),

                  raw_string(0x00, 0x60), raw_string(0x00, 0x61), raw_string(0x00, 0x62),
                  raw_string(0x00, 0x63), raw_string(0x00, 0x64), raw_string(0x00, 0x65),
                  raw_string(0x00, 0x66),

                  raw_string(0x00, 0x84), raw_string(0x00, 0x85), raw_string(0x00, 0x86),
                  raw_string(0x00, 0x87), raw_string(0x00, 0x88), raw_string(0x00, 0x89),

                  raw_string(0x00, 0x96), raw_string(0x00, 0x97), raw_string(0x00, 0x98),
                  raw_string(0x00, 0x99), raw_string(0x00, 0x9A), raw_string(0x00, 0x9B),

                  raw_string(0xC0, 0x01), raw_string(0xC0, 0x02), raw_string(0xC0, 0x03),
                  raw_string(0xC0, 0x04), raw_string(0xC0, 0x05), raw_string(0xC0, 0x06),
                  raw_string(0xC0, 0x07), raw_string(0xC0, 0x08), raw_string(0xC0, 0x09),
                  raw_string(0xC0, 0x0A), raw_string(0xC0, 0x0B), raw_string(0xC0, 0x0C),
                  raw_string(0xC0, 0x0D), raw_string(0xC0, 0x0E), raw_string(0xC0, 0x0F),

                  raw_string(0xC0, 0x10), raw_string(0xC0, 0x11), raw_string(0xC0, 0x12),
                  raw_string(0xC0, 0x13), raw_string(0xC0, 0x14), raw_string(0xC0, 0x15),
                  raw_string(0xC0, 0x16), raw_string(0xC0, 0x17), raw_string(0xC0, 0x18),
                  raw_string(0xC0, 0x19)

                );

## SSLv3 Display Names
sslv3_ciphers_disply = make_list
                    (

                      "SSL3_NULL_NULL_NULL : SSL_EXPORT",
                      "SSL3_RSA_NULL_MD5 : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_RSA_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_RSA_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_RC4_128_MD5 : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_RSA_RC4_128_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_RSA_RC2_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_IDEA_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_DSS_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_DH_DSS_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_DH_DSS_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_DH_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_DH_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_EDH_DSS_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_EDH_DSS_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_EDH_DSS_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_EDH_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_EDH_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_EDH_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_ADH_RC4_128_MD5 : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_ADH_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_ADH_DES_192_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_FZA_DMS_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_FZA_DMS_FZA_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_FZA_DMS_RC4_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_KRB5_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_KRB5_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_IDEA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_DES_64_CBC_MD5 : SSL_NOT_EXP : Medium Cipher",
                      "SSL3_KRB5_DES_192_CBC3_MD5 : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_RC4_128_MD5 : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_IDEA_128_CBC_MD5 : SSL_NOT_EXP : High Cipher",
                      "SSL3_KRB5_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_KRB5_RC2_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_KRB5_RC4_40_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_KRB5_DES_40_CBC_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_KRB5_RC2_40_CBC_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_KRB5_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_DH_DSS_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_RSA_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_DSS_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_RSA_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_DSS_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_DSS_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_DSS_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_EXPORT1024_WITH_RC4_56_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_EXPORT1024_WITH_DES_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_RSA_EXPORT1024_WITH_RC4_56_SHA : SSL_EXPORT : Medium Cipher",
                      "SSL3_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA : SSL_EXPORT : Weak Cipher",
                      "SSL3_DHE_DSS_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_DSS_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DH_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ADH_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_DH_DSS_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_DH_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_DHE_DSS_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_DHE_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ADH_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDH_ECDSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDH_ECDSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_ECDSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_ECDSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_ECDSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_ECDSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDHE_ECDSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_ECDSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_ECDSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_RSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDH_RSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_RSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_RSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_RSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_RSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDHE_RSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_RSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_RSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDHE_RSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_anon_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "SSL3_ECDH_anon_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_anon_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_anon_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "SSL3_ECDH_anon_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher"
                    );


## TLSv1 Display Names
tlsv1_ciphers_disply = make_list
                    (
                      "TLS1_NULL_NULL_NULL : SSL_EXPORT",
                      "TLS1_RSA_NULL_MD5 : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_RSA_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_RSA_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_RC4_128_MD5 : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_RSA_RC4_128_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_RSA_RC2_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_IDEA_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_DSS_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_DH_DSS_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_DH_DSS_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_DH_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_DH_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_EDH_DSS_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_EDH_DSS_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_EDH_DSS_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_EDH_RSA_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_EDH_RSA_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_EDH_RSA_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_ADH_RC4_128_MD5 : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_ADH_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_ADH_DES_192_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_FZA_DMS_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_FZA_DMS_FZA_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_FZA_DMS_RC4_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_KRB5_DES_64_CBC_SHA : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_KRB5_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_IDEA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_DES_64_CBC_MD5 : SSL_NOT_EXP : Medium Cipher",
                      "TLS1_KRB5_DES_192_CBC3_MD5 : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_RC4_128_MD5 : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_IDEA_128_CBC_MD5 : SSL_NOT_EXP : High Cipher",
                      "TLS1_KRB5_DES_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_KRB5_RC2_40_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_KRB5_RC4_40_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_KRB5_DES_40_CBC_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_KRB5_RC2_40_CBC_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_KRB5_RC4_40_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_DH_DSS_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_RSA_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_DSS_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_RSA_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_WITH_AES_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_DSS_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_DSS_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_RSA_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_WITH_AES_256_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_DSS_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_WITH_CAMELLIA_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_RSA_EXPORT1024_WITH_RC4_56_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5 : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_EXPORT1024_WITH_DES_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_RSA_EXPORT1024_WITH_RC4_56_SHA : SSL_EXPORT : Medium Cipher",
                      "TLS1_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA : SSL_EXPORT : Weak Cipher",
                      "TLS1_DHE_DSS_WITH_RC4_128_SHA : SSL_NOT_EXP : : High Cipher",
                      "TLS1_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_DSS_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DH_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ADH_WITH_CAMELLIA_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_DH_DSS_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_DH_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_DHE_DSS_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_DHE_RSA_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ADH_WITH_SEED_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDH_ECDSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDH_ECDSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_ECDSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_ECDSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_ECDSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_ECDSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDHE_ECDSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_ECDSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_ECDSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_ECDSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_RSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDH_RSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_RSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_RSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_RSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_RSA_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDHE_RSA_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_RSA_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_RSA_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDHE_RSA_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_anon_WITH_NULL_SHA : SSL_NOT_EXP : Weak Cipher",
                      "TLS1_ECDH_anon_WITH_RC4_128_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_anon_WITH_DES_192_CBC3_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_anon_WITH_AES_128_CBC_SHA : SSL_NOT_EXP : High Cipher",
                      "TLS1_ECDH_anon_WITH_AES_256_CBC_SHA : SSL_NOT_EXP : High Cipher"
                    );



## This function Constructs and sends ssl request with given
## cipher spec for given ssl version

function construct_ssl_req(SSL_VER, CIPHER)
{
  ssl_req = NULL;

  ## Construct SSLv2 Request with given Cipher Spec
  if(SSL_VER == "sslv2")
  {
    ## SSLv2 Version Client Hello Structure
    ## 0x80, Length(1), ClientHello(1), SSLVer(2), CipherSpecLength(2)
    ## SessionIDLength(2), ChallengeLength(2),
    ## CipherSpec(CipherSpecLength)
    ## Challenge(ChallengeLength)

    ssl_req = raw_string(
                          0x80, 0x1e, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
                          0x00, 0x00, 0x12,
                          CIPHER[0], CIPHER[1], CIPHER[2],

                          ## Challenge
                          0x00, 0x67,
                          0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec, 0x29,
                          0xcd, 0xba, 0xab, 0xf2, 0xfb, 0x00, 0x00, 0x00
                        );
  }

  ## Construct SSLv3 Request with given Cipher Spec
  else if(SSL_VER == "sslv3")
  {
     ## SSLv3 Client Hello Structure
     ## HandshakeType(1), SSLVer(2), Length(2), ClientHello(1), Length(3)
     ## SSLVer(2), RandomData(32), SessionID(1),
     ## CipherSuitLength(2), CipherSuit(CipherSuitLength),
     ## CompressionMethodLength(1), CompressionMethod(CompressionMethodLength)

     ssl_req = raw_string(
                           0x16, 0x03, 0x00, 0x00, 0x2d, 0x01, 0x00, 0x00,
                           0x29, 0x03, 0x00,

                           ## Random 32 byte data
                           0xec, 0x18, 0xdb, 0x5c, 0x02, 0x1a, 0xfe, 0x43,
                           0xfb, 0xfa, 0xaa, 0x3a, 0xfb, 0x29, 0xd1, 0xe6,
                           0x05, 0x3c, 0x7c, 0x94, 0x75, 0xd8, 0xbe, 0x61,
                           0x89, 0xf9, 0x5c, 0xbb, 0xa8, 0x99, 0x0f, 0x95,

                           0x00, 0x00, 0x02,
                           CIPHER[0], CIPHER[1],
                           0x01, 0x00, 0x00, 0x00
                         );
  }

  ## Construct TLSv1 Request with given Cipher Spec
  else if(SSL_VER == "tlsv1")
  {

     ## TLSv1
     ## TLSv1 Client Hello Structure
     ## HandshakeType(1), TLSVer(2), Length(2), ClientHello(1), Length(3)
     ## SSLVer(2), RandomData(32), SessionID(1),
     ## CipherSuitLength(2), CipherSuit(CipherSuitLength),
     ## CompressionMethodLength(1), CompressionMethod(CompressionMethodLength)

     ssl_req = raw_string(
                           0x16, 0x03, 0x01, 0x00, 0x2d, 0x01, 0x00, 0x00,
                           0x29, 0x03, 0x00,

                           ## Random 32 byte data
                           0xec, 0x18, 0xdb, 0x5c, 0x02, 0x1a, 0xfe, 0x43,
                           0xfb, 0xfa, 0xaa, 0x3a, 0xfb, 0x29, 0xd1, 0xe6,
                           0x05, 0x3c, 0x7c, 0x94, 0x75, 0xd8, 0xbe, 0x61,
                           0x89, 0xf9, 0x5c, 0xbb, 0xa8, 0x99, 0x0f, 0x95,

                           0x00, 0x00, 0x02,
                           CIPHER[0], CIPHER[1],
                           0x01, 0x00, 0x00, 0x00
                         );
  }

  return(ssl_req);
}


## This function sends given client hello request
## and return the server server_hello

function get_ssl_server_hello(ssl_req, sslPort)
{
    soc = open_sock_tcp(sslPort, transport: ENCAPS_IP);
    if(!soc){
      return FALSE;
    }

    send(socket:soc, data:ssl_req);
    server_res = recv(socket:soc, length:1024);
    close(soc);

    return (server_res);
}


## This function check for certain bytes in the server_hello and
## confirms server responded with proper server hello with
## proper cipher spec

function check_sslv2_cipher_spec_supported(server_hello)
{
  ## SSLv2 Server Hello Structure
  ## Lenght(2), ServerHelo(1), SessionIDHit(1), CertificateType(1), SSLVer(2),
  ## CertificateLength(2), CipherLength(2), ConnIDLength(2),
  ## Certificate(CertificateLength)
  ## CipherSpec(CipherLength),
  ## ConnID(ConnIDLength)

  sslv2_cipher_sup = FALSE;

  ## Check for ServerHello(4), SSL Ver(0x0002), Cipher Spec Length(3)
  ## If all the conditions specified menas, given cipher spec is supported
  ## by server
  if(ord(server_hello[2]) == 4 && ord(server_hello[5]) == 0 && ord(server_hello[6]) == 2 &&
     ord(server_hello[9]) == 0 && ord(server_hello[10]) == 3){
    sslv2_cipher_sup = TRUE;
  }
  return(sslv2_cipher_sup);
}


## This function check for certain bytes in the server_hello and
## confirms server responded with proper server hello with
## proper cipher spec

function check_sslv3_cipher_spec_supported(server_hello)
{

  ## ServerHello :
  ## HandshakeType(1), SSLVer(2), Length(2), ServerHello(1), Length(3)
  ## SSLVer(2), RandomData(32),
  ## SessionIDLength(1), SessionID(SessionIDLength)
  ## CipherSuite(Client-CipherSuitLength)
  ## CompressionMethod(1)
  ##
  ## Certificate :
  ## HandshakeType(1), SSLVer(2), Length(2), Certificate(1), Length(3)
  ## CertificatesLength(3), CertificateLength(3), Certificate(CertificateLength)
  ##
  ## ServerKey Exchange
  ## HandshakeType(1), SSLVer(2), Length(2), ServerKeyExchange(1), Length(3)
  ##
  ## ServerHello Done
  ## HandshakeType(1), SSLVer(2), Length(2), ServerHelloDone(1), Length(3)

  sslv3_cipher_sup = FALSE;

  ## Check for ServerHello(4), SSL Ver(0x0002), Cipher Spec Length(3)
  ## If all the conditions specified menas, given cipher spec is supported
  ## by server
  if(ord(server_hello[0]) == 22 && ord(server_hello[1]) == 3 && ord(server_hello[2]) == 0 &&
     ord(server_hello[5]) == 2 &&  ord(server_hello[9]) == 3){
    sslv3_cipher_sup = TRUE;
  }
  return(sslv3_cipher_sup);
}

## This function check for certain bytes in the server_hello and
## confirms server responded with proper server hello with
## proper cipher spec

function check_tlsv1_cipher_spec_supported(server_hello)
{

  ## ServerHello :
  ## HandshakeType(1), SSLVer(2), Length(2), ServerHello(1), Length(3)
  ## SSLVer(2), RandomData(32),
  ## SessionIDLength(1), SessionID(SessionIDLength)
  ## CipherSuite(Client-CipherSuitLength)
  ## CompressionMethod(1)
  ##
  ## Certificate :
  ## HandshakeType(1), SSLVer(2), Length(2), Certificate(1), Length(3)
  ## CertificatesLength(3), CertificateLength(3), Certificate(CertificateLength)
  ##
  ## ServerKey Exchange
  ## HandshakeType(1), SSLVer(2), Length(2), ServerKeyExchange(1), Length(3)
  ##
  ## ServerHello Done
  ## HandshakeType(1), SSLVer(2), Length(2), ServerHelloDone(1), Length(3)

  tlsv1_cipher_sup = FALSE;

  ## Check for ServerHello(4), SSL Ver(0x0002), Cipher Spec Length(3)
  ## If all the conditions specified menas, given cipher spec is supported
  ## by server
  if(ord(server_hello[0]) == 22 && ord(server_hello[1]) == 3 && ord(server_hello[2]) == 0 &&
     ord(server_hello[5]) == 2 &&  ord(server_hello[9]) == 3){
    tlsv1_cipher_sup = TRUE;
  }
  return(tlsv1_cipher_sup);
}

