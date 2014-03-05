# OpenVAS Vulnerability Test
# $Id: deb_2197_1.nasl 13 2013-10-27 12:16:33Z jan $
# Description: Auto-generated from advisory DSA 2197-1 (quagga)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "It has been discovered that the Quagga routing daemon contains two
denial-of-service vulnerabilities in its BGP implementation:

CVE-2010-1674
A crafted Extended Communities attribute triggers a null
pointer dereference which causes the BGP daemon to crash.
The crafted attributes are not propagated by the Internet
core, so only explicitly configured direct peers are able
to exploit this vulnerability in typical configurations.

CVE-2010-1675
The BGP daemon resets BGP sessions when it encounters
malformed AS_PATHLIMIT attributes, introducing a distributed
BGP session reset vulnerability which disrupts packet
forwarding.  Such malformed attributes are propagated by the
Internet core, and exploitation of this vulnerability is not
restricted to directly configured BGP peers.

This security update removes AS_PATHLIMIT processing from the BGP
implementation, preserving the configuration statements for backwards
compatibility.  (Standardization of this BGP extension was abandoned
long ago.)

For the oldstable distribution (lenny), these problems have been fixed
in version 0.99.10-1lenny5.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.17-2+squeeze2.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems will fixed soon.

We recommend that you upgrade your quagga packages.";
tag_summary = "The remote host is missing an update to quagga
announced via advisory DSA 2197-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202197-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(69333);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_cve_id("CVE-2010-1674", "CVE-2010-1675");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_name("Debian Security Advisory DSA 2197-1 (quagga)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2197-1 (quagga)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "insight" , value : tag_insight);
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
if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.10-1lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.10-1lenny5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"quagga", ver:"0.99.17-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"quagga-doc", ver:"0.99.17-2+squeeze2", rls:"DEB6.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
