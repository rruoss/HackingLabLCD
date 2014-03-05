# OpenVAS Vulnerability Test
# $Id: deb_1826_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1826-1 (eggdrop)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Several vulnerabilities have been discovered in eggdrop, an advanced IRC
robot. The Common Vulnerabilities and Exposures project identifies the
following problems:

CVE-2007-2807

It was discovered that eggdrop is vulnerable to a buffer overflow, which
could result in a remote user executing arbitrary code. The previous DSA
(DSA-1448-1) did not fix the issue correctly.

CVE-2009-1789

It was discovered that eggdrop is vulnerable to a denial of service
attack, that allows remote attackers to cause a crash via a crafted
PRIVMSG.

For the stable distribution (lenny), these problems have been fixed in
version 1.6.19-1.1+lenny1.

For the old stable distribution (etch), these problems have been fixed in
version 1.6.18-1etch2.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.19-1.2


We recommend that you upgrade your eggdrop package.";
tag_summary = "The remote host is missing an update to eggdrop
announced via advisory DSA 1826-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201826-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64378);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-07-15 04:21:35 +0200 (Wed, 15 Jul 2009)");
 script_cve_id("CVE-2007-2807", "CVE-2009-1789");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1826-1 (eggdrop)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1826-1 (eggdrop)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"eggdrop-data", ver:"1.6.18-1etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"eggdrop", ver:"1.6.18-1etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"eggdrop-data", ver:"1.6.19-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"eggdrop", ver:"1.6.19-1.1+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
