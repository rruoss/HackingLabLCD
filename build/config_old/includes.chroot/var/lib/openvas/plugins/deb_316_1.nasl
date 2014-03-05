# OpenVAS Vulnerability Test
# $Id: deb_316_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 316-1
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
tag_insight = "The nethack package is vulnerable to a buffer overflow exploited via a
long '-s' command line option.  This vulnerability could be used by an
attacker to gain gid 'games' on a system where nethack is installed.

Additionally, some setgid binaries in the nethack package have
incorrect permissions, which could allow a user who gains gid 'games'
to replace these binaries, potentially causing other users to execute
malicious code when they run nethack.

For the stable distribution (woody) these problems have been fixed in
version 3.4.0-3.0woody3.

For the old stable distribution (potato) problem xxx has been fixed in
version 3.3.0-7potato1.

For the unstable distribution (sid) these problems are fixed in
version 3.4.1-1.

We recommend that you update your nethack package.";
tag_summary = "The remote host is missing an update to nethack
announced via advisory DSA 316-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20316-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53605);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0358", "CVE-2003-0359");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 316-1 (nethack)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 316-1 (nethack)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"nethack", ver:"3.3.0-7potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nethack", ver:"3.4.0-3.0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nethack-common", ver:"3.4.0-3.0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nethack-gnome", ver:"3.4.0-3.0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nethack-qt", ver:"3.4.0-3.0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"nethack-x11", ver:"3.4.0-3.0woody3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
