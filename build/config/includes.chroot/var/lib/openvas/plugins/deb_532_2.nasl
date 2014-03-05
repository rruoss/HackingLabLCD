# OpenVAS Vulnerability Test
# $Id: deb_532_2.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 532-2
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
tag_insight = "Two vulnerabilities were discovered in libapache-mod-ssl:

CVE-2004-0488 - Stack-based buffer overflow in the
ssl_util_uuencode_binary function in ssl_util.c for Apache mod_ssl,
when mod_ssl is configured to trust the issuing CA, may allow remote
attackers to execute arbitrary code via a client certificate with a
long subject DN.

CVE-2004-0700 - Format string vulnerability in the ssl_log function
in ssl_engine_log.c in mod_ssl 2.8.19 for Apache 1.3.31 may allow
remote attackers to execute arbitrary messages via format string
specifiers in certain log messages for HTTPS.

This is a revision to DSA 531-1, due to a problem with a documentation
symlink in the previous version of the i386 binary package.

For the current stable distribution (woody), these problems have been
fixed in version 2.8.9-2.4.

For the unstable distribution (sid), CVE-2004-0488 was fixed in
version 2.8.18, and CVE-2004-0700 will be fixed soon.

We recommend that you update your libapache-mod-ssl package.";
tag_summary = "The remote host is missing an update to libapache-mod-ssl
announced via advisory DSA 532-2.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20532-2";

 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(53224);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 22:45:44 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2004-0488", "CVE-2004-0700");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Debian Security Advisory DSA 532-2 (libapache-mod-ssl)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 532-2 (libapache-mod-ssl)");

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
if ((res = isdpkgvuln(pkg:"libapache-mod-ssl-doc", ver:"2.8.9-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libapache-mod-ssl", ver:"2.8.9-2.4", rls:"DEB3.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
