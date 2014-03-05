# OpenVAS Vulnerability Test
# $Id: deb_731_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 731-1
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
tag_insight = "Several problems have been discovered in telnet clients that could be
exploited by malicious daemons the client connects to.  The Common
Vulnerabilities and Exposures project identifies the following
problems:

CVE-2005-0468

Ga�l Delalleau discovered a buffer overflow in the env_opt_add()
function that allow a remote attacker to execute arbitrary code.

CVE-2005-0469

Ga�l Delalleau discovered a buffer overflow in the handling of the
LINEMODE suboptions in telnet clients.  This can lead to the
execution of arbitrary code when connected to a malicious server.

For the stable distribution (woody) these problems have been fixed in
version 1.1-8-2.4.

For the testing distribution (sarge) these problems have been fixed in
version 1.2.2-11.2.

For the unstable distribution (sid) these problems have been fixed in
version 1.2.2-11.2.

We recommend that you upgrade your krb4 packages.";
tag_summary = "The remote host is missing an update to krb4
announced via advisory DSA 731-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20731-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53560);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-0468", "CVE-2005-0469");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 731-1 (krb4)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 731-1 (krb4)");

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
if ((res = isdpkgvuln(pkg:"kerberos4kth-docs", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-services", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-user", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-x11", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth1", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-clients", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-clients-x", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-dev", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-dev-common", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-kdc", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-kip", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-servers", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"kerberos4kth-servers-x", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libacl1-kerberos4kth", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkadm1-kerberos4kth", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkdb-1-kerberos4kth", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libkrb-1-kerberos4kth", ver:"1.1-8-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
