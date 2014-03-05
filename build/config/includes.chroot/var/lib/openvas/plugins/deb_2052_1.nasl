# OpenVAS Vulnerability Test
# $Id: deb_2052_1.nasl 14 2013-10-27 12:33:37Z jan $
# Description: Auto-generated from advisory DSA 2052-1 (krb5)
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
tag_insight = "Shawn Emery discovered that in MIT Kerberos 5 (krb5), a system for
authenticating users and services on a network, a null pointer
dereference flaw in the Generic Security Service Application Program
Interface (GSS-API) library could allow an authenticated remote attacker
to crash any server application using the GSS-API authentication
mechanism, by sending a specially-crafted GSS-API token with a missing
checksum field.

For the stable distribution (lenny), this problem has been fixed in
version 1.6.dfsg.4~beta1-5lenny4.

For the testing distribution (squeeze), this problem has been fixed in
version 1.8.1+dfsg-3.

For the testing distribution (sid), this problem has been fixed in
version 1.8.1+dfsg-3.

We recommend that you upgrade your krb5 packages.";
tag_summary = "The remote host is missing an update to krb5
announced via advisory DSA 2052-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202052-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(67405);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-03 22:55:24 +0200 (Thu, 03 Jun 2010)");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
 script_cve_id("CVE-2010-1321");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 2052-1 (krb5)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 2052-1 (krb5)");

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
if ((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-ftpd", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-telnetd", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-clients", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-user", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb53", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"krb5-rsh-server", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm55", ver:"1.6.dfsg.4~beta1-5lenny4", rls:"DEB5.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
