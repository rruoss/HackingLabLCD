# OpenVAS Vulnerability Test
# $Id: deb_2118_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2118-1 (subversion)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "Kamesh Jayachandran and C. Michael Pilat discovered that the mod_dav_svn
module of subversion, a version control system, is not properly enforcing
access rules which are scope-limited to named repositories.  If the
SVNPathAuthz option is set to short_circuit set this may enable an
unprivileged attacker to bypass intended access restrictions and disclose
or modify repository content.

As a workaround it is also possible to set SVNPathAuthz to on but be
advised that this can result in a performance decrease for large
repositories.


For the stable distribution (lenny), this problem has been fixed in
version 1.5.1dfsg1-5.

For the testing distribution (squeeze), this problem has been fixed in
version 1.6.12dfsg-2.

For the unstable distribution (sid), this problem has been fixed in
version 1.6.12dfsg-2.


We recommend that you upgrade your samba packages.";
tag_summary = "The remote host is missing an update to subversion
announced via advisory DSA 2118-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202118-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(68459);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-17 03:33:48 +0100 (Wed, 17 Nov 2010)");
 script_tag(name:"cvss_base", value:"6.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2010-3315");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2118-1 (subversion)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2118-1 (subversion)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"libsvn-doc", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion-tools", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-ruby1.8", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"subversion", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn1", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache2-svn", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python-subversion", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-perl", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-dev", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libsvn-java", ver:"1.5.1dfsg1-5", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
