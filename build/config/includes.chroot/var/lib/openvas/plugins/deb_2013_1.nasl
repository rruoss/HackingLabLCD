# OpenVAS Vulnerability Test
# $Id: deb_2013_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2013-1 (egroupware)
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
tag_insight = "Nahuel Grisolia discovered two vulnerabilities in Egroupware, a web-based
groupware suite: Missing input sanitising in the spellchecker integration
may lead to the execution of arbitrary commands and a cross-site scripting
vulnerability was discovered in the login page.

For the stable distribution (lenny), these problems have been fixed in
version 1.4.004-2.dfsg-4.2.

The upcoming stable distribution (squeeze), no longer contains egroupware
packages.

We recommend that you upgrade your egroupware packages.";
tag_summary = "The remote host is missing an update to egroupware
announced via advisory DSA 2013-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202013-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67035);
 script_cve_id("CVE-2010-3313","CVE-2010-3314");
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-03-16 17:25:39 +0100 (Tue, 16 Mar 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2013-1 (egroupware)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2013-1 (egroupware)");

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
if ((res = isdpkgvuln(pkg:"egroupware-bookmarks", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-felamimail", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-mydms", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-polls", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-calendar", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-developer-tools", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-etemplate", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-emailadmin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpsysinfo", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-resources", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-news-admin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-filemanager", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-registration", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-sitemgr", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpbrain", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-core", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-infolog", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-tracker", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-wiki", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-sambaadmin", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-addressbook", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-timesheet", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-manual", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-projectmanager", ver:"1.4.004-2.dfsg-4.2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
