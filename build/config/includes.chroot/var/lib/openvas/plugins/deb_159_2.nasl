# OpenVAS Vulnerability Test
# $Id: deb_159_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 159-2
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
tag_insight = "The bugfix we distributed in DSA 159-1 unfortunately caused Python to
sometimes behave improperly when a non-executable file existed earlier
in the path and an executable file of the same name existed later in
the path.  Zack Weinberg fixed this in the Python source.  For
reference, here's the original advisory text:

Zack Weinberg discovered an insecure use of a temporary file in
os._execvpe from os.py. It uses a predictable name which could
lead execution of arbitrary code.

This problem has been fixed in several versions of Python: For the
current stable distribution (woody) it has been fixed in version
1.5.2-23.2 of Python 1.5, in version 2.1.3-3.2 of Python 2.1 and in
version 2.2.1-4.2 of Python 2.2. For the old stable distribution
(potato) this has been fixed in version 1.5.2-10potato13 for Python
1.5. For the unstable distribution (sid) this has been fixed in
version 1.5.2-25 of Python 1.5, in version 2.1.3-9 of Python 2.1 and
in version 2.2.1-11 of Python 2.2. Python 2.3 is not affected by the
original problem.

We recommend that you upgrade your Python packages.";
tag_summary = "The remote host is missing an update to python
announced via advisory DSA 159-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20159-2";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53730);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:24:46 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2002-1119");
 script_bugtraq_id(5581);
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 159-2 (python)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 159-2 (python)");

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
if ((res = isdpkgvuln(pkg:"python-base", ver:"1.5.2-10potato13", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python1.5", ver:"1.5.2-23.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.1", ver:"2.1.3-3.2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"python2.2", ver:"2.2.1-4.2", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
