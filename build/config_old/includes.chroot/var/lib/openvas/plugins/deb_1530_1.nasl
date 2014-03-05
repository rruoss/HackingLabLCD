# OpenVAS Vulnerability Test
# $Id: deb_1530_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 1530-1 (cupsys)
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
tag_insight = "Several local/remote vulnerabilities have been discovered in cupsys, the
Common Unix Printing System.  The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2008-0047
Heap-based buffer overflow in CUPS, when printer sharing is enabled,
allows remote attackers to execute arbitrary code via crafted search
expressions.

CVE-2008-0882
Double free vulnerability in the process_browse_data function in CUPS
1.3.5 allows remote attackers to cause a denial of service (daemon
crash) and possibly execute arbitrary code via crafted packets to the
cupsd port (631/udp), related to an unspecified manipulation of a
remote printer.

For the stable distribution (etch), these problems have been fixed in
version 1.2.7-4etch3

We recommend that you upgrade your cupsys packages.";
tag_summary = "The remote host is missing an update to cupsys
announced via advisory DSA 1530-1.";

tag_solution = "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%201530-1";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(60619);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-03-27 18:25:13 +0100 (Thu, 27 Mar 2008)");
 script_cve_id("CVE-2008-0047", "CVE-2008-0882");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 1530-1 (cupsys)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 1530-1 (cupsys)");

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
if ((res = isdpkgvuln(pkg:"cupsys-common", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-gnutls10", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-dbg", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-bsd", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys-client", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cupsys", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsys2-dev", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"libcupsimage2-dev", ver:"1.2.7-4etch3", rls:"DEB4.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
