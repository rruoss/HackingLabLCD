# OpenVAS Vulnerability Test
# $Id: deb_250_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 250-1
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
tag_insight = "Hironori Sakamoto, one of the w3m developers, found two security
vulnerabilities in w3m and associated programs.  The w3m browser does
not properly escape HTML tags in frame contents and img alt
attributes.  A malicious HTML frame or img alt attribute may deceive a
user to send his local cookies which are used for configuration.  The
information is not leaked automatically, though.

For the stable distribution (woody) these problems have been fixed in
version 0.3.p23.3-1.5.  Please note that the update also contains an
important patch to make the program work on the powerpc platform again.

The old stable distribution (potato) is not affected by these
problems.

For the unstable distribution (sid) these problems have been fixed in
version 0.3.p24.17-3 and later.

We recommend that you upgrade your w3mmee-ssl packages.";
tag_summary = "The remote host is missing an update to w3mmee-ssl
announced via advisory DSA 250-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20250-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53325);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1335", "CVE-2002-1348");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 250-1 (w3mmee-ssl)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 250-1 (w3mmee-ssl)");

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
if ((res = isdpkgvuln(pkg:"w3mmee-ssl", ver:"0.3.p23.3-1.5", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
