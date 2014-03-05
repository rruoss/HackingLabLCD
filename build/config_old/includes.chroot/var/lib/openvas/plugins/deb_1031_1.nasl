# OpenVAS Vulnerability Test
# $Id: deb_1031_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1031-1
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
tag_solution = "For the stable distribution (sarge) these problems have been fixed in
version 0.8.6c-7sarge3.

For the unstable distribution these problems will be fixed soon.

We recommend that you upgrade your cacti package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201031-1";
tag_summary = "The remote host is missing an update to cacti
announced via advisory DSA 1031-1.

Several vulnerabilities have been discovered in libphp-adodb, the
'adodb' database abstraction layer for PHP, which is embedded in
cacti, a frontend to rrdtool for monitoring systems and services.  The
Common Vulnerabilities and Exposures project identifies the following
problems:

CVE-2006-0146

Andreas Sandblad discovered that improper user input sanitisation
results in a potential remote SQL injection vulnerability enabling
an attacker to compromise applications, access or modify data, or
exploit vulnerabilities in the underlying database implementation.
This requires the MySQL root password to be empty.  It is fixed by
limiting access to the script in question.

CVE-2006-0147

A dynamic code evaluation vulnerability allows remote attackers to
execute arbitrary PHP functions via the 'do' parameter.

CVE-2006-0410

Andy Staudacher discovered an SQL injection vulnerability due to
insufficient input sanitising that allows remote attackers to
execute arbitrary SQL commands.

CVE-2006-0806

GulfTech Security Research discovered multiple cross-site
scripting vulnerabilities due to improper user-supplied input
sanitisation.  Attackers can exploit these vulnerabilities to
cause arbitrary scripts to be executed in the browser of an
unsuspecting user's machine, or result in the theft of
cookie-based authentication credentials.

The old stable distribution (woody) is not affected by these problems.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(56530);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:09:45 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2006-0146", "CVE-2006-0147", "CVE-2006-0410", "CVE-2006-0806");
 script_bugtraq_id(16187,16364,16720);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 1031-1 (cacti)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1031-1 (cacti)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2006 E-Soft Inc. http://www.securityspace.com");
 script_family("Debian Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
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
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.8.6c-7sarge3", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
