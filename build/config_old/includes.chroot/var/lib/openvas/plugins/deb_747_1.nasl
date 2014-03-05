# OpenVAS Vulnerability Test
# $Id: deb_747_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 747-1
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
tag_insight = "A vulernability has been identified in the xmlrpc library included in
the egroupware package. This vulnerability could lead to the execution
of arbitrary commands on the server running egroupware.

The old stable distribution (woody) did not include egroupware.

For the current stable distribution (sarge), this problem is fixed in
version 1.0.0.007-2.dfsg-2sarge1.

For the unstable distribution (sid), this problem is fixed in version
1.0.0.007-3.dfsg-1.

We recommend that you upgrade your egroupware package.";
tag_summary = "The remote host is missing an update to egroupware
announced via advisory DSA 747-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20747-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(54322);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(14088);
 script_cve_id("CVE-2005-1921");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 747-1 (egroupware)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 747-1 (egroupware)");

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
if ((res = isdpkgvuln(pkg:"egroupware", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-forum", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-ftp", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-sitemgr", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-jinn", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-stocks", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-news-admin", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-emailadmin", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-addressbook", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpsysinfo", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-manual", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-filemanager", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-tts", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-comic", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-fudforum", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-infolog", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-bookmarks", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpbrain", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-core", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-messenger", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-etemplate", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-calendar", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-headlines", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-ldap", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-wiki", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-email", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-projects", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-phpldapadmin", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-felamimail", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-polls", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-registration", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"egroupware-developer-tools", ver:"1.0.0.007-2.dfsg-2sarge1", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
