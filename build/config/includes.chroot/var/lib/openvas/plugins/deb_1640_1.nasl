# OpenVAS Vulnerability Test
# $Id: deb_1640_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1640-1 (python-django)
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
tag_insight = "Simon Willison discovered that in Django, a Python web framework, the
feature to retain HTTP POST data during user reauthentication allowed
a remote attacker to perform unauthorized modification of data through
cross site request forgery. The is possible regardless of the Django
plugin to prevent cross site request forgery being enabled. The Common
Vulnerabilities and Exposures project identifies this issue as
CVE-2008-3909.

In this update the affected feature is disabled; this is in accordance
with upstream's preferred solution for this situation.

This update takes the opportunity to also include a relatively minor
denial of service attack in the internationalisaton framework, known
as CVE-2007-5712.

For the stable distribution (etch), these problems have been fixed in
version 0.95.1-1etch2.

For the unstable distribution (sid), these problems have been fixed in
version 1.0-1.

We recommend that you upgrade your python-django package.";
tag_summary = "The remote host is missing an update to python-django
announced via advisory DSA 1640-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201640-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(61642);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 17:42:31 +0200 (Wed, 24 Sep 2008)");
 script_cve_id("CVE-2008-3909", "CVE-2007-5712");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1640-1 (python-django)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1640-1 (python-django)");

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
if ((res = isdpkgvuln(pkg:"python-django", ver:"0.95.1-1etch2", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
