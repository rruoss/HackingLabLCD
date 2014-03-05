# OpenVAS Vulnerability Test
# $Id: deb_1374_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1374-1
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
tag_insight = "Several vulnerabilities have been discovered in jffnms, a web-based
Network Management System for IP networks.  The Common Vulnerabilities
and Exposures project identifies the following problems:

CVE-2007-3189

Cross-site scripting (XSS) vulnerability in auth.php, which allows
a remote attacker to inject arbitrary web script or HTML via the
user parameter.

CVE-2007-3190

Multiple SQL injection vulnerabilities in auth.php, which allow
remote attackers to execute arbitrary SQL commands via the
user and password parameters.

CVE-2007-3192

Direct requests to URLs make it possible for remote attackers to
access configuration information, bypassing login restrictions.


For the stable distribution (etch), these problems have been fixed in version
0.8.3dfsg.1-2.1etch1

For the unstable distribution (sid), these problems have been fixed in
version 0.8.3dfsg.1-4.

We recommend that you upgrade your jffnms package.";
tag_summary = "The remote host is missing an update to jffnms
announced via advisory DSA 1374-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201374-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(58595);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:19:52 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2007-3189", "CVE-2007-3190", "CVE-2007-3191", "CVE-2007-3192");
 script_tag(name:"cvss_base", value:"9.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1374-1 (jffnms)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1374-1 (jffnms)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2007 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"jffnms", ver:"0.8.3dfsg.1-2.1etch1", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
