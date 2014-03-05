# OpenVAS Vulnerability Test
# $Id: deb_023_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 023-1
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
tag_insight = "1. People at WireX have found several potential insecure uses of
temporary files in programs provided by INN2.  Some of them only
lead to a vulnerability to symlink attacks if the temporary
directory was set to /tmp or /var/tmp, which is the case in many
installations, at least in Debian packages.  An attacker could
overwrite any file owned by the news system administrator,
i.e. owned by news.news.

2. Michal Zalewski found an exploitable buffer overflow with regard
to cancel messages and their verification.  This bug did only show
up if 'verifycancels' was enabled in inn.conf which is not the
default and has been disrecommended by upstream.

3. Andi Kleen found a bug in INN2 that makes innd crash for two byte
headers.  There is a chance this can only be exploited with uucp.

We recommend you upgrade your inn2 packages immediately.";
tag_summary = "The remote host is missing an update to inn2
announced via advisory DSA 023-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20023-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53786);
 script_cve_id("CVE-2001-0361");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 14:24:38 +0100 (Thu, 17 Jan 2008)");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 023-1 (inn2)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 023-1 (inn2)");

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
if ((res = isdpkgvuln(pkg:"inn2-dev", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inn2-inews", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"inn2", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"task-news-server", ver:"2.2.2.2000.01.31-4.1", rls:"DEB2.2")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
