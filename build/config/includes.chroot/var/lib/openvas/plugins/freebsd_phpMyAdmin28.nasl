#
#VID ed536336-1c57-11e1-86f4-e0cb4e266481
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID ed536336-1c57-11e1-86f4-e0cb4e266481
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisories, and are Copyright (c) the respective author(s)
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
tag_insight = "The following package is affected: phpMyAdmin

CVE-2011-4634
Multiple cross-site scripting (XSS) vulnerabilities in phpMyAdmin
3.4.x before 3.4.8 allow remote attackers to inject arbitrary web
script or HTML via (1) a crafted database name, related to the
Database Synchronize panel; (2) a crafted database name, related to
the Database rename panel; (3) a crafted SQL query, related to the
table overview panel; (4) a crafted SQL query, related to the view
creation dialog; (5) a crafted column type, related to the table
search dialog; or (6) a crafted column type, related to the create
index dialog.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.phpmyadmin.net/home_page/security/PMASA-2011-18.php
http://www.vuxml.org/freebsd/ed536336-1c57-11e1-86f4-e0cb4e266481.html";
tag_summary = "The remote host is missing an update to the system
as announced in the referenced advisory.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(70597);
 script_cve_id("CVE-2011-4634");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_version("$Revision: 18 $");
 script_name("FreeBSD Ports: phpMyAdmin");


 script_description(desc);

 script_summary("FreeBSD Ports: phpMyAdmin");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
 script_family("FreeBSD Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("ssh/login/freebsdrel", "login/SSH/success");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-bsd.inc");

txt = "";
vuln = 0;
bver = portver(pkg:"phpMyAdmin");
if(!isnull(bver) && revcomp(a:bver, b:"3.4")>0 && revcomp(a:bver, b:"3.4.8.r1")<0) {
    txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
