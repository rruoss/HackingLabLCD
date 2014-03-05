#
#ADV FreeBSD-SA-06:23.openssl.asc
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
#

include("revisions-lib.inc");
tag_insight = "FreeBSD includes software from the OpenSSL Project.  The OpenSSL Project is
a collaborative effort to develop a robust, commercial-grade, full-featured,
and Open Source toolkit implementing the Secure Sockets Layer (SSL v2/v3)
and Transport Layer Security (TLS v1) protocols as well as a full-strength
general purpose cryptography library.

Several problems have been found in OpenSSL:

1. During the parsing of certain invalid ASN1 structures an error condition
is mishandled, possibly resulting in an infinite loop.  [CVE-2006-2937]

2. A buffer overflow exists in the SSL_get_shared_ciphers function.
[CVE-2006-3738]

3. A NULL pointer may be dereferenced in the SSL version 2 client code.
[CVE-2006-4343]

In addition, many applications using OpenSSL do not perform any validation
of the lengths of public keys being used. [CVE-2006-2940]";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-06:23.openssl.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-06:23.openssl.asc";

                                                                                
if(description)
{
 script_id(57475);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2006-2937");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 name = "FreeBSD Security Advisory (FreeBSD-SA-06:23.openssl.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-06:23.openssl.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 family = "FreeBSD Local Security Checks";
 script_family(family);
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdpatchlevel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");
vuln = 0;
if(patchlevelcmp(rel:"6.1", patchlevel:"8")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"6.0", patchlevel:"13")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.5", patchlevel:"6")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.4", patchlevel:"20")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.3", patchlevel:"35")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.11", patchlevel:"23")<0) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
