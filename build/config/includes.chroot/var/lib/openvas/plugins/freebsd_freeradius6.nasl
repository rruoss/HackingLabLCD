#
#VID 3bbbe3aa-fbeb-11e1-8bd8-0022156e8794
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 3bbbe3aa-fbeb-11e1-8bd8-0022156e8794
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
tag_insight = "The following package is affected: freeradius";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://freeradius.org/security.html
http://www.pre-cert.de/advisories/PRE-SA-2012-06.txt
http://www.vuxml.org/freebsd/3bbbe3aa-fbeb-11e1-8bd8-0022156e8794.html";
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
 script_id(72199);
 script_cve_id("CVE-2012-3547");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-09-15 04:25:48 -0400 (Sat, 15 Sep 2012)");
 script_name("FreeBSD Ports: freeradius");

 script_description(desc);

 script_summary("FreeBSD Ports: freeradius");

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
vuln = 0;
txt = "";
bver = portver(pkg:"freeradius");
if(!isnull(bver) && revcomp(a:bver, b:"2.1.10")>=0 && revcomp(a:bver, b:"2.1.12_2")<0) {
    txt += "Package freeradius version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99);
}