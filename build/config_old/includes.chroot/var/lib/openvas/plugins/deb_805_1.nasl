# OpenVAS Vulnerability Test
# $Id: deb_805_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 805-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 2.0.54-5.

For the unstable distribution (sid) these problems have been fixed in
version 2.0.54-5.

We recommend that you upgrade your apache2 packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20805-1";
tag_summary = "The remote host is missing an update to apache2
announced via advisory DSA 805-1.

Several problems have been discovered in Apache2, the next generation,
scalable, extendable web server.  The Common Vulnerabilities and
Exposures project identifies the following problems:

CVE-2005-1268
Marc Stern discovered an off-by-one error in the mod_ssl
Certificate Revocation List (CRL) verification callback.  When
Apache is configured to use a CRL this can be used to cause a
denial of service.

CVE-2005-2088
A vulnerability has been discovered in the Apache web server.
When it is acting as an HTTP proxy, it allows remote attackers to
poison the web cache, bypass web application firewall protection,
and conduct cross-site scripting attacks, which causes Apache to
incorrectly handle and forward the body of the request.

CVE-2005-2700
A problem has been discovered in mod_ssl, which provides strong
cryptography (HTTPS support) for Apache that allows remote
attackers to bypass access restrictions.

CVE-2005-2728
The byte-range filter in Apache 2.0 allows remote attackers to
cause a denial of service via an HTTP header with a large Range
field.

The old stable distribution (woody) does not contain Apache2 packages.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(55261);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:03:37 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-1268", "CVE-2005-2088", "CVE-2005-2700", "CVE-2005-2728");
 script_bugtraq_id(14660);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 805-1 (apache2)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 805-1 (apache2)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"apache2-doc", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-threadpool", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-common", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-perchild", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-prefork", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-mpm-worker", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-prefork-dev", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-threaded-dev", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"apache2-utils", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapr0-dev", ver:"2.0.54-5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
