#
#VID 192609c8-0c51-11df-82a0-00248c9b4be7
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 192609c8-0c51-11df-82a0-00248c9b4be7
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
tag_insight = "The following packages are affected:
   ircd-ratbox
   ircd-ratbox-devel

CVE-2009-4016
Integer underflow in the clean_string function in irc_string.c in (1)
IRCD-hybrid 7.2.2 and 7.2.3, (2) ircd-ratbox before 2.2.9, and (3)
oftc-hybrid before 1.6.8, when flatten_links is disabled, allows
remote attackers to execute arbitrary code or cause a denial of
service (daemon crash) via a LINKS command.

CVE-2010-0300
cache.c in ircd-ratbox before 2.2.9 allows remote attackers to cause a
denial of service (NULL pointer dereference and daemon crash) via a
HELP command.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.debian.org/security/2010/dsa-1980
http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000890.html
http://lists.ratbox.org/pipermail/ircd-ratbox/2010-January/000891.html
http://www.vuxml.org/freebsd/192609c8-0c51-11df-82a0-00248c9b4be7.html";
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
 script_id(66819);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-02-10 21:51:26 +0100 (Wed, 10 Feb 2010)");
 script_cve_id("CVE-2009-4016", "CVE-2010-0300");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: ircd-ratbox");


 script_description(desc);

 script_summary("FreeBSD Ports: ircd-ratbox");

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
bver = portver(pkg:"ircd-ratbox");
if(!isnull(bver) && revcomp(a:bver, b:"2.2.9")<0) {
    txt += 'Package ircd-ratbox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ircd-ratbox-devel");
if(!isnull(bver) && revcomp(a:bver, b:"3.0.6")<0) {
    txt += 'Package ircd-ratbox-devel version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
