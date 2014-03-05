# OpenVAS Vulnerability Test
# $Id: deb_468_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 468-1
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
tag_insight = "Ulf Harnhammar discovered a number of vulnerabilities in emil, a
filter for converting Internet mail messages.  The vulnerabilities
fall into two categories:

- CVE-2004-0152 - Buffer overflows in (1) the encode_mime function,
(2) the encode_uuencode function, (3) the decode_uuencode
function.  These bugs could allow a carefully crafted email message
to cause the execution of arbitrary code supplied with the message
when it is acted upon by emil.

- CVE-2004-0153 - Format string bugs in statements which print
various error messages.  The exploit potential of these bugs has
not been established, and is probably configuration-dependent.

For the stable distribution (woody) these problems have been fixed in
version 2.1.0-beta9-11woody1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you update your emil package.";
tag_summary = "The remote host is missing an update to emil
announced via advisory DSA 468-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20468-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53165);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0152", "CVE-2004-0153");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 468-1 (emil)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 468-1 (emil)");

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
if ((res = isdpkgvuln(pkg:"emil", ver:"2.1.0-beta9-11woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
