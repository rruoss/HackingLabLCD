# OpenVAS Vulnerability Test
# $Id: deb_1468_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1468-1 (tomcat5.5)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
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
tag_insight = "Several remote vulnerabilities have been discovered in the Tomcat
servlet and JSP engine. The Common Vulnerabilities and Exposures project
identifies the following problems:

CVE-2008-0128

Olaf Kock discovered that HTTPS encryption was insufficiently
enforced for single-sign-on cookies, which could result in
information disclosure.

CVE-2007-2450

It was discovered that the Manager and Host Manager web applications
performed insufficient input sanitising, which could lead to cross-
site scripting.

This update also adapts the tomcat5.5-webapps package to the tightened
JULI permissions introduced in the previous tomcat5.5 DSA. However, it
should be noted, that the tomcat5.5-webapps is for demonstration and
documentation purposes only and should not be used for production
systems.

For the unstable distribution (sid), these problems will be fixed soon.

For the stable distribution (etch), these problems have been fixed in
version 5.5.20-2etch2.

The old stable distribution (sarge) doesn't contain tomcat5.5.

We recommend that you upgrade your tomcat5.5 packages.";
tag_summary = "The remote host is missing an update to tomcat5.5
announced via advisory DSA 1468-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201468-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60212);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-31 16:11:48 +0100 (Thu, 31 Jan 2008)");
 script_cve_id("CVE-2008-0128", "CVE-2007-2450");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 1468-1 (tomcat5.5)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1468-1 (tomcat5.5)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"tomcat5.5-admin", ver:"5.5.20-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libtomcat5.5-java", ver:"5.5.20-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat5.5", ver:"5.5.20-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"tomcat5.5-webapps", ver:"5.5.20-2etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
