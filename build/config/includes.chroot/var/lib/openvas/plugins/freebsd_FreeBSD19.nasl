#
#VID 2ae114de-c064-11e1-b5e0-000c299b62e1
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 2ae114de-c064-11e1-b5e0-000c299b62e1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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

include("revisions-lib.inc");
tag_insight = "The following package is affected: FreeBSD

CVE-2011-4576
The SSL 3.0 implementation in OpenSSL before 0.9.8s and 1.x before
1.0.0f does not properly initialize data structures for block cipher
padding, which might allow remote attackers to obtain sensitive
information by decrypting the padding data sent by an SSL peer.
CVE-2011-4619
The Server Gated Cryptography (SGC) implementation in OpenSSL before
0.9.8s and 1.x before 1.0.0f does not properly handle handshake
restarts, which allows remote attackers to cause a denial of service
via unspecified vectors.
CVE-2011-4109
Double free vulnerability in OpenSSL 0.9.8 before 0.9.8s, when
X509_V_FLAG_POLICY_CHECK is enabled, allows remote attackers to have
an unspecified impact by triggering failure of a policy check.
CVE-2012-0884
The implementation of Cryptographic Message Syntax (CMS) and PKCS #7
in OpenSSL before 0.9.8u and 1.x before 1.0.0h does not properly
restrict certain oracle behavior, which makes it easier for
context-dependent attackers to decrypt data via a Million Message
Attack (MMA) adaptive chosen ciphertext attack.
CVE-2012-2110
The asn1_d2i_read_bio function in crypto/asn1/a_d2i_fp.c in OpenSSL
before 0.9.8v, 1.0.0 before 1.0.0i, and 1.0.1 before 1.0.1a does not
properly interpret integer data, which allows remote attackers to
conduct buffer overflow attacks, and cause a denial of service (memory
corruption) or possibly have unspecified other impact, via crafted DER
data, as demonstrated by an X.509 certificate or an RSA public key.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(71533);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-4576", "CVE-2011-4619", "CVE-2011-4109", "CVE-2012-0884", "CVE-2012-2110");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: FreeBSD");

 script_description(desc);

 script_summary("FreeBSD Ports: FreeBSD");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
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
txt = "";
bver = portver(pkg:"FreeBSD");
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4_8")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1")>=0 && revcomp(a:bver, b:"8.1_10")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.2")>=0 && revcomp(a:bver, b:"8.2_8")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.3")>=0 && revcomp(a:bver, b:"8.3_2")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"9.0")>=0 && revcomp(a:bver, b:"9.0_2")<0) {
    txt += "Package FreeBSD version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
