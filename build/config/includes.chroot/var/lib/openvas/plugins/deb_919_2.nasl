# OpenVAS Vulnerability Test
# $Id: deb_919_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 919-2
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
version 7.13.2-2sarge5.

For the unstable distribution (sid) these problems have been fixed in
version 7.15.1-1.

We recommend that you upgrade your libcurl packages.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20919-2";
tag_summary = "The remote host is missing an update to curl
announced via advisory DSA 919-2.

The upstream developer of curl, a multi-protocol file transfer
library, informed us that the former correction to several off-by-one
errors are not sufficient.  For completeness please find the original
bug description below:

Stefan Esser discovered several off-by-one errors that allows
local users to trigger a buffer overflow and cause a denial of
service or bypass PHP security restrictions via certain URLs.

For the old stable distribution (woody) these problems have been fixed in
version 7.9.5-1woody2.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56397);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:07:13 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-4077");
 script_bugtraq_id(15756);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 919-2 (curl)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 919-2 (curl)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"curl", ver:"7.9.5-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl-dev", ver:"7.9.5-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl2", ver:"7.9.5-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"curl", ver:"7.13.2-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3", ver:"7.13.2-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dbg", ver:"7.13.2-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-dev", ver:"7.13.2-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcurl3-gssapi", ver:"7.13.2-2sarge5", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
