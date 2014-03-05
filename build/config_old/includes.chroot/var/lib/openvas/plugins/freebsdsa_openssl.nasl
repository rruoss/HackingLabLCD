#
#ADV FreeBSD-SA-03:18.openssl.asc
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
tag_insight = "FreeBSD includes software from the OpenSSL Project.  The OpenSSL
Project is a collaborative effort to develop a robust, commercial-
grade, full-featured, and Open Source toolkit implementing the Secure
Sockets Layer (SSL v2/v3) and Transport Layer Security (TLS v1)
protocols as well as a full-strength general purpose cryptography
library.

This advisory addresses four separate flaws recently fixed in OpenSSL.
The flaws are described in the following excerpt from the OpenSSL.org
advisory (see references):

  1. Certain ASN.1 encodings that are rejected as invalid by the
  parser can trigger a bug in the deallocation of the corresponding
  data structure, corrupting the stack. This can be used as a denial
  of service attack. It is currently unknown whether this can be
  exploited to run malicious code. This issue does not affect OpenSSL
  0.9.6.

  2. Unusual ASN.1 tag values can cause an out of bounds read
  under certain circumstances, resulting in a denial of service
  vulnerability.

  3. A malformed public key in a certificate will crash the verify
  code if it is set to ignore public key decoding errors. Public
  key decode errors are not normally ignored, except for
  debugging purposes, so this is unlikely to affect production
  code. Exploitation of an affected application would result in a
  denial of service vulnerability.

  4. Due to an error in the SSL/TLS protocol handling, a server
  will parse a client certificate when one is not specifically
  requested. This by itself is not strictly speaking a vulnerability
  but it does mean that *all* SSL/TLS servers that use OpenSSL can be
  attacked using vulnerabilities 1, 2 and 3 even if they don't enable
  client authentication.";
tag_solution = "Upgrade your system to the appropriate stable release
or security branch dated after the correction date

https://secure1.securityspace.com/smysecure/catid.html?in=FreeBSD-SA-03:18.openssl.asc";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory FreeBSD-SA-03:18.openssl.asc";

                                                                                
if(description)
{
 script_id(52641);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "FreeBSD Security Advisory (FreeBSD-SA-03:18.openssl.asc)";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "FreeBSD Security Advisory (FreeBSD-SA-03:18.openssl.asc)";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if(patchlevelcmp(rel:"5.1", patchlevel:"10")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"5.0", patchlevel:"18")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.8", patchlevel:"13")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.7", patchlevel:"23")<0) {
    vuln = 1;
}
if(patchlevelcmp(rel:"4.6.2", patchlevel:"26")<0) {
    vuln = 1;
}

if(vuln) {
    security_hole(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
