# OpenVAS Vulnerability Test
# $Id: deb_764_1.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Auto-generated from advisory DSA 764-1
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
version 0.8.6c-7sarge2.

For the unstable distribution (sid) these problems have been fixed in
version 0.8.6e-1.

We recommend that you upgrade your cacti package.

 https://secure1.securityspace.com/smysecure/catid.html?in=DSA%20764-1";
tag_summary = "The remote host is missing an update to cacti
announced via advisory DSA 764-1.

Several vulnerabilities have been discovered in cacti, a round-robin
database (RRD) tool that helps create graphs from database
information.  The Common Vulnerabilities and Exposures Project
identifies the following problems:

CVE-2005-1524

Maciej Piotr Falkiewicz and an anonymous researcher discovered an
input validation bug that allows an attacker to include arbitrary
PHP code from remote sites which will allow the execution of
arbitrary code on the server running cacti.

CVE-2005-1525

Due to mising input validation cacti allows a remote attacker to
insert arbitrary SQL statements.

CVE-2005-1526

Maciej Piotr Falkiewicz discovered an input validation bug that
allows an attacker to include arbitrary PHP code from remote sites
which will allow the execution of arbitrary code on the server
running cacti.

CVE-2005-2148

Stefan Esser discovered that the update for the abovely mentioned
vulnerabilities does not perform proper input validation to
protect against common attacks.

CVE-2005-2149

Stefan Esser discovered that the update for CVE-2005-1525 allows
remote attackers to modify session information to gain privileges
and disable the use of addslashes to protect against SQL
injection.

For the old stable distribution (woody) these problems have been fixed in
version 0.6.7-2.5.";


 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(54411);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-01-17 23:00:53 +0100 (Thu, 17 Jan 2008)");
 script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526", "CVE-2005-2148", "CVE-2005-2149");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Debian Security Advisory DSA 764-1 (cacti)");


 script_description(desc);

 script_summary("Debian Security Advisory DSA 764-1 (cacti)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.6.7-2.5", rls:"DEB3.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.8.6c-7sarge2", rls:"DEB3.1")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
