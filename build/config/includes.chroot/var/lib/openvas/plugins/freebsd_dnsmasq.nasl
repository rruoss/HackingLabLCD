#
#VID 80aa98e0-97b4-11de-b946-0030843d3802
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 80aa98e0-97b4-11de-b946-0030843d3802
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
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
tag_insight = "The following package is affected: dnsmasq

CVE-2009-2957
Heap-based buffer overflow in the tftp_request function in tftp.c in
dnsmasq before 2.50, when --enable-tftp is used, might allow remote
attackers to execute arbitrary code via a long filename in a TFTP
packet, as demonstrated by a read (aka RRQ) request.
CVE-2009-2958
The tftp_request function in tftp.c in dnsmasq before 2.50, when
--enable-tftp is used, allows remote attackers to cause a denial of
service (NULL pointer dereference and daemon crash) via a TFTP read
(aka RRQ) request with a malformed blksize option.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.coresecurity.com/content/dnsmasq-vulnerabilities
https://rhn.redhat.com/errata/RHSA-2009-1238.html
http://www.vuxml.org/freebsd/80aa98e0-97b4-11de-b946-0030843d3802.html";
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
 script_id(64829);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-09-09 02:15:49 +0200 (Wed, 09 Sep 2009)");
 script_cve_id("CVE-2009-2957", "CVE-2009-2958");
 script_bugtraq_id(36121,36120);
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: dnsmasq");


 script_description(desc);

 script_summary("FreeBSD Ports: dnsmasq");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"dnsmasq");
if(!isnull(bver) && revcomp(a:bver, b:"2.50")<0) {
    txt += 'Package dnsmasq version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
