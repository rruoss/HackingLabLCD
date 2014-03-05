# OpenVAS Vulnerability Test
# $Id: deb_1049_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1049-1
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largerly excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge5.

For the unstable distribution (sid) these problems have be fixed soon.

We recommend that you upgrade your ethereal packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201049-1";
tag_summary = "The remote host is missing an update to ethereal
announced via advisory DSA 1049-1.

Gerald Combs reported several vulnerabilities in ethereal, a popular
network traffic analyser.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2006-1932

The OID printing routine is susceptible to an off-by-one error.

CVE-2006-1933

The UMA and BER dissectors could go into an infinite loop.

CVE-2006-1934

The Network Instruments file code could overrun a buffer.

CVE-2006-1935

The COPS dissector contains a potential buffer overflow.

CVE-2006-1936

The telnet dissector contains a buffer overflow.

CVE-2006-1937

Bugs in the SRVLOC and AIM dissector, and in the statistics
counter could crash ethereal.

CVE-2006-1938

Null pointer dereferences in the SMB PIPE dissector and when
reading a malformed Sniffer capture could crash ethereal.

CVE-2006-1939

Null pointer dereferences in the ASN.1, GSM SMS, RPC and
ASN.1-based dissector and an invalid display filter could crash
ethereal.

CVE-2006-1940

The SNDCP dissector could cause an unintended abortion.

For the old stable distribution (woody) these problems have been fixed in
version 0.9.4-1woody15.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56670);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-1932", "CVE-2006-1933", "CVE-2006-1934", "CVE-2006-1935", "CVE-2006-1936", "CVE-2006-1937", "CVE-2006-1938", "CVE-2006-1939", "CVE-2006-1940");
 script_bugtraq_id(17682);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1049-1 (ethereal)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1049-1 (ethereal)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.9.4-1woody15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.9.4-1woody15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.9.4-1woody15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.9.4-1woody15", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal", ver:"0.10.10-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-common", ver:"0.10.10-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"ethereal-dev", ver:"0.10.10-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tethereal", ver:"0.10.10-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
