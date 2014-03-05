# OpenVAS Vulnerability Test
# $Id: deb_436_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 436-2
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
tag_insight = "Several vulnerabilities have been fixed in the mailman package:

- CVE-2003-0038 - potential cross-site scripting via certain CGI
parameters (not known to be exploitable in this version)

- CVE-2003-0965 - cross-site scripting in the administrative
interface

- CVE-2003-0991 - certain malformed email commands could cause the
mailman process to crash

The cross-site scripting vulnerabilities could allow an attacker to
perform administrative operations without authorization, by stealing a
session cookie.

In the process of fixing these vulnerabilities for DSA 436-1, a bug
was introduced which could cause mailman to crash on certain malformed
messages.

For the current stable distribution (woody) this problem has been
fixed in version 2.0.11-1woody8.

The update for the unstable distribution did not share the bug
introduced in DSA 436-1.

We recommend that you update your mailman package.";
tag_summary = "The remote host is missing an update to mailman
announced via advisory DSA 436-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20436-2";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53144);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:41:51 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0991", "CVE-2003-0965", "CVE-2003-0038");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 436-2 (mailman)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 436-2 (mailman)");

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
if ((res = isdpkgvuln(pkg:"mailman", ver:"2.0.11-1woody8", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
