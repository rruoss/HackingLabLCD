#
#VID 1f6ee708-0d22-11e1-b5bd-14dae938ec40
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1f6ee708-0d22-11e1-b5bd-14dae938ec40
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

CVE-2011-4107
The simplexml_load_string function in the XML import plug-in
(libraries/import/xml.php) in phpMyAdmin 3.4.x before 3.4.7.1 and
3.3.x before 3.3.10.5 allows remote authenticated users to read
arbitrary files via XML data containing external entity references,
aka an XML external entity (XXE) injection attack.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.phpmyadmin.net/home_page/security/PMASA-2011-17.php
http://www.vuxml.org/freebsd/1f6ee708-0d22-11e1-b5bd-14dae938ec40.html";
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
 script_id(70603);
 script_cve_id("CVE-2011-4107");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"risk_factor", value:"Medium");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
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
if(!isnull(bver) && revcomp(a:bver, b:"3.4")>0 && revcomp(a:bver, b:"3.4.7.1")<0) {
    txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.3.10.5")<0) {
    txt += 'Package phpMyAdmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
