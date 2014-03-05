# OpenVAS Vulnerability Test
# $Id: deb_144_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 144-1
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
tag_insight = "A problem with wwwoffle has been discovered.  The web proxy didn't
handle input data with negative Content-Length settings properly which
causes the processing child to crash.  It is at this time not obvious
how this can lead to an exploitable vulnerability; however, it's better
to be safe than sorry, so here's an update.

Additionally, in the woody version empty passwords will be treated as
wrong when trying to authenticate.  In the woody version we also
replaced CanonicaliseHost() with the latest routine from 2.7d, offered
by upstream.  This stops bad IPv6 format IP addresses in URLs from
causing problems (memory overwriting, potential exploits).

This problem has been fixed in version 2.5c-10.4 for the old stable
distribution (potato), in version 2.7a-1.2 for the current stable
distribution (woody) and in version 2.7d-1 for the unstable
distribution (sid).

We recommend that you upgrade your wwwoffle packages.";
tag_summary = "The remote host is missing an update to wwwoffle
announced via advisory DSA 144-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20144-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53580);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_bugtraq_id(5260);
 script_cve_id("CVE-2002-0818");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 144-1 (wwwoffle)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 144-1 (wwwoffle)");

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
if ((res = isdpkgvuln(pkg:"wwwoffle", ver:"2.5c-10.4", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wwwoffle", ver:"2.7a-1.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
