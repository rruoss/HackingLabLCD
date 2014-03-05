#
#VID 3c8d1e5b-b673-11e1-be25-14dae9ebcf89
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 3c8d1e5b-b673-11e1-be25-14dae9ebcf89
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
tag_insight = "The following package is affected: asterisk10

CVE-2012-3553
chan_skinny.c in the Skinny (aka SCCP) channel driver in Asterisk Open
Source 10.x before 10.5.1 allows remote authenticated users to cause a
denial of service (NULL pointer dereference and daemon crash) by
sending a Station Key Pad Button message and closing a connection in
off-hook mode, a related issue to CVE-2012-2948.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://downloads.digium.com/pub/security/AST-2012-009.html
https://www.asterisk.org/security
http://www.vuxml.org/freebsd/3c8d1e5b-b673-11e1-be25-14dae9ebcf89.html";
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
 script_id(71537);
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_cve_id("CVE-2012-3553");
 script_tag(name:"risk_factor", value:"Medium");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-08-10 03:22:17 -0400 (Fri, 10 Aug 2012)");
 script_name("FreeBSD Ports: asterisk10");

 script_description(desc);

 script_summary("FreeBSD Ports: asterisk10");

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
bver = portver(pkg:"asterisk10");
if(!isnull(bver) && revcomp(a:bver, b:"10")>0 && revcomp(a:bver, b:"10.5.1")<0) {
    txt += "Package asterisk10 version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_warning(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
