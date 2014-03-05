# OpenVAS Vulnerability Test
# $Id: deb_2747.nasl 55 2013-11-11 15:38:51Z mime $
# Auto-generated from advisory DSA 2747-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

tag_affected  = "cacti on Debian Linux";
tag_insight   = "Cacti is a complete frontend to rrdtool, it stores all of the necessary
information to create graphs and populates them with data in a MySQL
database. The frontend is completely PHP driven. Along with being able
to maintain Graphs, Data Sources, and Round Robin Archives in a
database, cacti handles the data gathering also. There is also SNMP
support for those used to creating traffic graphs with MRTG.";
tag_solution  = "For the oldstable distribution (squeeze), these problems have been fixed in
version 0.8.7g-1+squeeze3.

For the stable distribution (wheezy), these problems have been fixed in
version 0.8.8a+dfsg-5+deb7u2.

For the unstable distribution (sid), these problems have been fixed in
version 0.8.8b+dfsg-3.

We recommend that you upgrade your cacti packages.";
tag_summary   = "Two vulnerabilities were discovered in Cacti, a web interface for
graphing of monitoring systems:

CVE-2013-5588 
install/index.php and cacti/host.php suffered from Cross-Site
Scripting vulnerabilities.

CVE-2013-5589 
cacti/host.php contained an SQL injection vulnerability, allowing
an attacker to execute SQL code on the database used by Cacti.";
tag_vuldetect = "This check tests the installed software version using the apt package manager.";

desc = "Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

if(description)
{
    script_id(892747);
    script_version("$Revision: 55 $");
    script_cve_id("CVE-2013-5588", "CVE-2013-5589");
    script_name("Debian Security Advisory DSA 2747-1 (cacti - several vulnerabilities");
    script_tag(name: "check_type", value:"authenticated package test");
    script_tag(name: "last_modification", value:"$Date: 2013-11-11 16:38:51 +0100 (Mo, 11. Nov 2013) $");
    script_tag(name: "creation_date", value:"2013-08-31 00:00:00 +0200 (Sa, 31 Aug 2013)");
    script_tag(name: "cvss_base", value:"7.5");
    script_tag(name: "cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name: "risk_factor", value:"High");

    script_description(desc);
    script_xref(name: "URL", value: "http://www.debian.org/security/2013/dsa-2747.html");

    script_summary("Debian Security Advisory DSA 2747-1 (cacti - several vulnerabilities)");

    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2013 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("HostDetails/OS/cpe:/o:debian:debian_linux", "login/SSH/success", "ssh/login/packages");
    if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
        script_tag(name: "affected",  value: tag_affected);
        script_tag(name: "insight",   value: tag_insight);
#        script_tag(name: "impact",    value: tag_impact);
        script_tag(name: "solution",  value: tag_solution);
        script_tag(name: "summary",   value: tag_summary);
        script_tag(name: "vuldetect", value: tag_vuldetect);
    }

    exit(0);
}

include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.8.7g-1+squeeze3", rls:"DEB6.0")) != NULL) {
    report += res;
}
if ((res = isdpkgvuln(pkg:"cacti", ver:"0.8.8a+dfsg-5+deb7u2", rls:"DEB7.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
