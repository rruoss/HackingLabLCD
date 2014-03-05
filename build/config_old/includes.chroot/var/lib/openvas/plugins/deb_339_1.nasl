# OpenVAS Vulnerability Test
# $Id: deb_339_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 339-1
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
tag_insight = "NOTE: due to a combination of administrative problems, this advisory
was erroneously released with the identifier 'DSA-337-1'.  DSA-337-1
correctly refers to an earlier advisory regarding gtksee.

semi, a MIME library for GNU Emacs, does not take appropriate
security precautions when creating temporary files.  This bug could
potentially be exploited to overwrite arbitrary files with the
privileges of the user running Emacs and semi, potentially with
contents supplied by the attacker.

wemi is a fork of semi, and contains the same bug.

For the stable distribution (woody) this problem has been fixed in
semi version 1.14.3.cvs.2001.08.10-1woody2 and wemi version
1.14.0.20010802wemiko-1.3.

For the unstable distribution (sid) this problem has been fixed in
semi version 1.14.5+20030609-1.  The unstable distribution does not
contain a wemi package.

We recommend that you update your semi and wemi packages.";
tag_summary = "The remote host is missing an update to semi, wemi
announced via advisory DSA 339-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20339-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53628);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:36:24 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0440");
 script_tag(name:"cvss_base", value:"4.6");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Debian Security Advisory DSA 339-1 (semi, wemi)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 339-1 (semi, wemi)");

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
if ((res = isdpkgvuln(pkg:"semi", ver:"1.14.3.cvs.2001.08.10-1woody2", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"wemi", ver:"1.14.0.20010802wemiko-1.3", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(0);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
