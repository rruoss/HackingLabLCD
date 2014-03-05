# OpenVAS Vulnerability Test
# $Id: deb_1883_2.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1883-2 (nagios2)
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
tag_insight = "The previous nagios2 update introduced a regression, which caused
status.cgi to segfault when used directly without specifying the 'host'
variable. This update fixes the problem. For reference the original
advisory text follows.


Several vulnerabilities have been found in nagios2, ahost/service/network
monitoring and management system. The Common Vulnerabilities and
Exposures project identifies the following problems:


Several cross-site scripting issues via several parameters were
discovered in the CGI scripts, allowing attackers to inject arbitrary
HTML code. In order to cover the different attack vectors, these issues
have been assigned CVE-2007-5624, CVE-2007-5803 and CVE-2008-1360.



For the oldstable distribution (etch), these problems have been fixed in
version 2.6-2+etch5.

The stable distribution (lenny) does not include nagios2 and nagios3 is
not affected by these problems.

The testing distribution (squeeze) and the unstable distribution (sid)
do not contain nagios2 and nagios3 is not affected by these problems.


We recommend that you upgrade your nagios2 packages.";
tag_summary = "The remote host is missing an update to nagios2
announced via advisory DSA 1883-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201883-2";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64868);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-15 22:46:32 +0200 (Tue, 15 Sep 2009)");
 script_cve_id("CVE-2007-5624", "CVE-2007-5803", "CVE-2008-1360");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1883-2 (nagios2)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1883-2 (nagios2)");

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
if ((res = isdpkgvuln(pkg:"nagios2-common", ver:"2.6-2+etch5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2-doc", ver:"2.6-2+etch5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2", ver:"2.6-2+etch5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nagios2-dbg", ver:"2.6-2+etch5", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
