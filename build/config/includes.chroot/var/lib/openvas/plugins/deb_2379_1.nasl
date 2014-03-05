# OpenVAS Vulnerability Test
# $Id: deb_2379_1.nasl 12 2013-10-27 11:15:33Z jan $
# Description: Auto-generated from advisory DSA 2379-1 (krb5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "It was discovered that the Key Distribution Center (KDC) in Kerberos 5
crashes when processing certain crafted requests:

CVE-2011-1528
When the LDAP backend is used, remote users can trigger
a KDC daemon crash and denial of service.

CVE-2011-1529
When the LDAP or Berkeley DB backend is used, remote users
can trigger a NULL pointer dereference in the KDC daemon
and a denial of service.

The oldstable distribution (lenny) is not affected by these problems.

For the stable distribution (squeeze), these problems have been fixed
in version 1.8.3+dfsg-4squeeze5.

For the testing distribution (wheezy) and the unstable distribution
(sid), these problems have been fixed in version 1.10+dfsg~alpha1-1.

We recommend that you upgrade your krb5 packages.";
tag_summary = "The remote host is missing an update to krb5
announced via advisory DSA 2379-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202379-1";

if(description)
{
 script_id(70698);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_cve_id("CVE-2011-1528", "CVE-2011-1529");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-11 03:26:12 -0500 (Sat, 11 Feb 2012)");
 script_name("Debian Security Advisory DSA 2379-1 (krb5)");

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary("Debian Security Advisory DSA 2379-1 (krb5)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
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
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit7", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit7", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-4", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb53", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.8.3+dfsg-4squeeze5", rls:"DEB6.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-admin-server", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-doc", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-gss-samples", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-kdc-ldap", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-locales", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-multidev", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-pkinit", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"krb5-user", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssapi-krb5-2", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libgssrpc4", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libk5crypto3", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5clnt-mit8", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkadm5srv-mit8", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkdb5-6", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-3", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dbg", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5-dev", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}
if((res = isdpkgvuln(pkg:"libkrb5support0", ver:"1.10+dfsg~beta1-2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if(report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}