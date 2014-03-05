# OpenVAS Vulnerability Test
# $Id: deb_1937_1.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory DSA 1937-1 (gforge)
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
tag_insight = "It was discovered that gforge, collaborative development tool, is prone
to a cross-site scripting attack via the helpname parameter. Beside
fixing this issue, the update also introduces some additional input
sanitising. However, there are no known attack vectors.


For the stable distribution (lenny), these problem have been fixed in
version 4.7~rc2-7lenny2.

The oldstable distribution (etch), these problems have been fixed in
version 4.5.14-22etch12.

For the testing distribution (squeeze) and the unstable distribution
(sid), these problems have been fixed in version 4.8.1-3.


We recommend that you upgrade your gforge packages.";
tag_summary = "The remote host is missing an update to gforge
announced via advisory DSA 1937-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201937-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(66297);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-11-23 20:51:51 +0100 (Mon, 23 Nov 2009)");
 script_cve_id("CVE-2009-3303");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1937-1 (gforge)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1937-1 (gforge)");

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
if ((res = isdpkgvuln(pkg:"gforge-web-apache", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-common", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-shell-ldap", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-exim", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-ldap-openldap", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-courier", ver:"4.5.14-22etch12", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-exim4", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmcvs", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-common", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-mediawiki", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-postfix", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-ftp-proftpd", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-shell-postgresql", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-web-apache", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-plugin-scmsvn", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-web-apache2", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-db-postgresql", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-lists-mailman", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-dns-bind9", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"gforge-mta-courier", ver:"4.7~rc2-7lenny2", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
