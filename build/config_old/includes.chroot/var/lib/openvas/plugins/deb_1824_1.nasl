# OpenVAS Vulnerability Test
# $Id: deb_1824_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1824-1 (phpmyadmin)
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
tag_insight = "Several remote vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2009-1150

Cross site scripting vulnerability in the export page allow for an
attacker that can place crafted cookies with the user to inject
arbitrary web script or HTML.

CVE-2009-1151

Static code injection allows for a remote attacker to inject arbitrary
code into phpMyAdmin via the setup.php script. This script is in Debian
under normal circumstances protected via Apache authentication.
However, because of a recent worm based on this exploit, we are patching
it regardless, to also protect installations that somehow still expose
the setup.php script.

For the old stable distribution (etch), these problems have been fixed in
version 2.9.1.1-11.

For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny1.

For the unstable distribution (sid), these problems have been fixed in
version 3.1.3.1-1.

We recommend that you upgrade your phpmyadmin package.";
tag_summary = "The remote host is missing an update to phpmyadmin
announced via advisory DSA 1824-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201824-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(64312);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-06-30 00:29:55 +0200 (Tue, 30 Jun 2009)");
 script_cve_id("CVE-2009-1150", "CVE-2009-1151");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1824-1 (phpmyadmin)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1824-1 (phpmyadmin)");

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
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.9.1.1-11", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"phpmyadmin", ver:"2.11.8.1-5+lenny1", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
