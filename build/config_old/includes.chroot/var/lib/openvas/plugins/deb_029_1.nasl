# OpenVAS Vulnerability Test
# $Id: deb_029_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 029-1
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
tag_insight = "The following problems have been reported for the version of proftpd in
Debian 2.2 (potato):

1. There is a memory leak in the SIZE command which can result in a
denial of service, as reported by Wojciech Purczynski. This is only a
problem if proftpd cannot write to its scoreboard file; the default
configuration of proftpd in Debian is not vulnerable.

2. A similar memory leak affects the USER command, also as reported by
Wojciech Purczynski. The proftpd in Debian 2.2 is susceptible to this
vulnerability; an attacker can cause the proftpd daemon to crash by
exhausting its available memory.

3. There were some format string vulnerabilities reported by Przemyslaw
Frasunek. These are not known to have exploits, but have been corrected
as a precaution.

All three of the above vulnerabilities have been corrected in
proftpd-1.2.0pre10-2potato1. We recommend you upgrade your proftpd
package immediately.";
tag_summary = "The remote host is missing an update to proftpd
announced via advisory DSA 029-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20029-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53791);
 script_cve_id("CVE-2001-0136","CVE-2001-0318");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 029-1 (proftpd)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 029-1 (proftpd)");

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
if ((res = isdpkgvuln(pkg:"proftpd", ver:"1.2.0pre10-2potato1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
