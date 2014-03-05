#
#VID 96e776c7-e75c-11df-8f26-00151735203a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 96e776c7-e75c-11df-8f26-00151735203a
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: otrs

CVE-2010-2080
Multiple cross-site scripting (XSS) vulnerabilities in Open Ticket
Request System (OTRS) 2.3.x before 2.3.6 and 2.4.x before 2.4.8 allow
remote authenticated users to inject arbitrary web script or HTML via
unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://otrs.org/advisory/OSA-2010-02-en/
http://otrs.org/advisory/OSA-2010-03-en/
http://www.vuxml.org/freebsd/96e776c7-e75c-11df-8f26-00151735203a.html";
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
 script_id(68496);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-11-17 03:33:48 +0100 (Wed, 17 Nov 2010)");
 script_tag(name:"cvss_base", value:"3.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
 script_cve_id("CVE-2010-2080", "CVE-2010-4071");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("FreeBSD Ports: otrs");


 script_description(desc);

 script_summary("FreeBSD Ports: otrs");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2010 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"otrs");
if(!isnull(bver) && revcomp(a:bver, b:"2.3")>0 && revcomp(a:bver, b:"2.4.9")<0) {
    txt += 'Package otrs version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
