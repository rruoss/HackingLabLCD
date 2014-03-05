#
#VID 98bd69c3-834b-11d8-a41f-0020ed76ef5a
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from vuxml or freebsd advisories
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following packages are affected:
   courier
   courier-imap
   sqwebmail

CVE-2004-0224
Multiple buffer overflows in (1) iso2022jp.c or (2) shiftjis.c for
Courier-IMAP before 3.0.0, Courier before 0.45, and SqWebMail before
4.0.0 may allow remote attackers to execute arbitrary code 'when
Unicode character is out of BMP range.'";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/iso2022jp.c?rev=1.10&view=markup
http://cvs.sourceforge.net/viewcvs.py/courier/libs/unicode/shiftjis.c?rev=1.6&view=markup
http://secunia.com/advisories/11087
http://www.osvdb.org/4194
http://www.osvdb.org/6927
http://www.vuxml.org/freebsd/98bd69c3-834b-11d8-a41f-0020ed76ef5a.html";
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
 script_id(52431);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2004-0224");
 script_bugtraq_id(9845);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: courier");


 script_description(desc);

 script_summary("FreeBSD Ports: courier");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"courier");
if(!isnull(bver) && revcomp(a:bver, b:"0.45")<0) {
    txt += 'Package courier version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"courier-imap");
if(!isnull(bver) && revcomp(a:bver, b:"3.0,1")<0) {
    txt += 'Package courier-imap version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sqwebmail");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")<0) {
    txt += 'Package sqwebmail version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
