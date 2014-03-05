# OpenVAS Vulnerability Test
# $Id: deb_246_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 246-1
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
tag_insight = "The developers of tomcat discovered several problems in tomcat version
3.x.  The Common Vulnerabilities and Exposures project identifies the
following problems:

. CVE-2003-0042: A maliciously crafted request could return a
directory listing even when an index.html, index.jsp, or other
welcome file is present.  File contents can be returned as well.

. CVE-2003-0043: A malicious web application could read the contents
of some files outside the web application via its web.xml file in
spite of the presence of a security manager.  The content of files
that can be read as part of an XML document would be accessible.

. CVE-2003-0044: A cross-site scripting vulnerability was discovered
in the included sample web application that allows remote attackers
to execute arbitrary script code.

For the stable distribution (woody) this problem has been fixed in
version 3.3a-4.1.

The old stable distribution (potato) does not contain tomcat packages.

For the unstable distribution (sid) this problem has been fixed in
version 3.3.1a-1.

We recommend that you upgrade your tomcat package.";
tag_summary = "The remote host is missing an update to tomcat
announced via advisory DSA 246-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20246-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53322);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0042", "CVE-2003-0043", "CVE-2003-0044");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 246-1 (tomcat)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 246-1 (tomcat)");

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
if ((res = isdpkgvuln(pkg:"tomcat", ver:"3.3a-4woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache-mod-jk", ver:"3.3a-4woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
