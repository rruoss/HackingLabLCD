#
#VID 56ba8728-f987-11de-b28d-00215c6a37bb
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 56ba8728-f987-11de-b28d-00215c6a37bb
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
   pear-Net_Ping
   pear-Net_Traceroute

CVE-2009-4024
Argument injection vulnerability in the ping function in Ping.php in
the Net_Ping package before 2.4.5 for PEAR allows remote attackers to
execute arbitrary shell commands via the host parameter.

CVE-2009-4025
Argument injection vulnerability in the traceroute function in
Traceroute.php in the Net_Traceroute package before 0.21.2 for PEAR
allows remote attackers to execute arbitrary shell commands via the
host parameter.  NOTE: some of these details are obtained from third
party information.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://pear.php.net/advisory20091114-01.txt
http://www.vuxml.org/freebsd/56ba8728-f987-11de-b28d-00215c6a37bb.html";
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
 script_id(66644);
 script_version("$Revision: 14 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-07 13:59:33 +0100 (Thu, 07 Jan 2010)");
 script_cve_id("CVE-2009-4024", "CVE-2009-4025");
 script_bugtraq_id(37093,37094);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: pear-Net_Ping");


 script_description(desc);

 script_summary("FreeBSD Ports: pear-Net_Ping");

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
bver = portver(pkg:"pear-Net_Ping");
if(!isnull(bver) && revcomp(a:bver, b:"2.4.5")<0) {
    txt += 'Package pear-Net_Ping version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pear-Net_Traceroute");
if(!isnull(bver) && revcomp(a:bver, b:"0.21.2")<0) {
    txt += 'Package pear-Net_Traceroute version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
