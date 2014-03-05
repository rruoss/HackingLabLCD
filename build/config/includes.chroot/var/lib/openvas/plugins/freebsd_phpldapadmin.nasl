#
#VID edf47177-fe3f-11e0-a207-0014a5e3cda6
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID edf47177-fe3f-11e0-a207-0014a5e3cda6
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
tag_insight = "The following package is affected: phpldapadmin";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://packetstormsecurity.org/files/106120/phpldapadmin-inject.txt
http://sourceforge.net/tracker/?func=detail&aid=3417184&group_id=61828&atid=498546
http://www.vuxml.org/freebsd/edf47177-fe3f-11e0-a207-0014a5e3cda6.html";
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
 script_id(70614);
 script_tag(name:"check_type", value:"authenticated package test");
 script_version("$Revision: 18 $");
 script_tag(name:"cvss_base", value:"7.5"); 
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: phpldapadmin");


 script_description(desc);

 script_summary("FreeBSD Ports: phpldapadmin");

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
bver = portver(pkg:"phpldapadmin");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.0")>=0 && revcomp(a:bver, b:"1.2.1.1_1,1")<0) {
    txt += 'Package phpldapadmin version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
