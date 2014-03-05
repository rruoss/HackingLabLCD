# OpenVAS Vulnerability Test
# $Id: deb_228_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 228-1
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
tag_insight = "Ilia Alshanetsky discovered several buffer overflows in libmcrypt, a
decryption and encryption library, that originates in from improper or
lacking input validation.  By passing input which is longer then
expected to a number of functions (multiple functions are affected)
the user can successful make libmcrypt crash and may be able to insert
arbitrary, malicious, code which will be executed under the user
libmcrypt runs as, e.g. inside a web server.

Another vulnerability exists in the way libmcrypt loads algorithms via
libtool.  When different algorithms are loaded dynamically, each time
an algorithm is loaded a small part of memory is leaked.  In a
persistant enviroment (web server) this could lead to a memory
exhaustion attack that will exhaust all avaliable memory by launching
repeated requests at an application utilizing the mcrypt library.

For the current stable distribution (woody) this problem has been
fixed in version 2.5.0-1woody1.

The old stable distribution (potato) does not contain libmcrypt packages.

For the unstable distribution (sid) these problems have been fixed in
version 2.5.5-1.

We recommend that you upgrade your libmcrypt packages.";
tag_summary = "The remote host is missing an update to libmcrypt
announced via advisory DSA 228-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20228-1";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53310);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:28:10 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2003-0031", "CVE-2003-0032");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 228-1 (libmcrypt)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 228-1 (libmcrypt)");

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
if ((res = isdpkgvuln(pkg:"libmcrypt-dev", ver:"2.5.0-1woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libmcrypt4", ver:"2.5.0-1woody1", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
