#
#VID f5a76faf-244c-11dd-b143-0211d880e350
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
tag_insight = "The following package is affected: libvorbis

CVE-2008-1419
Xiph.org libvorbis 1.2.0 and earlier does not properly handle a zero
value for codebook.dim, which allows remote attackers to cause a
denial of service (crash or infinite loop) or trigger an integer
overflow.

CVE-2008-1420
Integer overflow in residue partition value (aka partvals) evaluation
in Xiph.org libvorbis 1.2.0 and earlier allows remote attackers to
execute arbitrary code via a crafted OGG file, which triggers a heap
overflow.

CVE-2008-1423
Integer overflow in a certain quantvals and quantlist calculation in
Xiph.org libvorbis 1.2.0 and earlier allows remote attackers to cause
a denial of service (crash) or execute arbitrary code via a crafted
OGG file with a large virtual space for its codebook, which triggers a
heap overflow.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://rhn.redhat.com/errata/RHSA-2008-0270.html
http://www.vuxml.org/freebsd/f5a76faf-244c-11dd-b143-0211d880e350.html";
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
 script_id(61057);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2008-1419", "CVE-2008-1420", "CVE-2008-1423");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("FreeBSD Ports: libvorbis");


 script_description(desc);

 script_summary("FreeBSD Ports: libvorbis");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2008 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"libvorbis");
if(!isnull(bver) && revcomp(a:bver, b:"1.2.0_2,3")<0) {
    txt += 'Package libvorbis version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
