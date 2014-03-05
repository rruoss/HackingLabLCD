#
#VID 1c4cab30-5468-11e1-9fb7-003067b2972c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 1c4cab30-5468-11e1-9fb7-003067b2972c
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
tag_insight = "The following package is affected: bip

CVE-2012-0806
Buffer overflow in Bip 0.8.8 and earlier might allow remote
authenticated users to execute arbitrary code via vectors involving a
series of TCP connections that triggers use of many open file
descriptors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://projects.duckcorp.org/projects/bip/repository/revisions/222a33cb84a2e52ad55a88900b7895bf9dd0262c
https://projects.duckcorp.org/issues/269
http://www.vuxml.org/freebsd/1c4cab30-5468-11e1-9fb7-003067b2972c.html";
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
 script_id(70729);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2012-0806");
 script_tag(name:"risk_factor", value:"High");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:19 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: bip");


 script_description(desc);

 script_summary("FreeBSD Ports: bip");

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
txt = "";
bver = portver(pkg:"bip");
if(!isnull(bver) && revcomp(a:bver, b:"0.8.8")<=0) {
    txt += 'Package bip version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
