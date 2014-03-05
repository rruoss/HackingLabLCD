#
#VID fee94342-4638-11e1-9f47-00e0815b8da8
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID fee94342-4638-11e1-9f47-00e0815b8da8
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
tag_insight = "The following package is affected: FreeBSD

CVE-2011-2895
The LZW decompressor in (1) the BufCompressedFill function in
fontfile/decompress.c in X.Org libXfont before 1.4.4 and (2)
compress/compress.c in 4.3BSD, as used in zopen.c in OpenBSD before
3.8, FreeBSD, NetBSD 4.0.x and 5.0.x before 5.0.3 and 5.1.x before
5.1.1, FreeType 2.1.9, and other products, does not properly handle
code words that are absent from the decompression table when
encountered, which allows context-dependent attackers to trigger an
infinite loop or a heap-based buffer overflow, and possibly execute
arbitrary code, via a crafted compressed stream, a related issue to
CVE-2006-1168 and CVE-2011-2896.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.";
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
 script_id(70743);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-2895");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-12 07:27:20 -0500 (Sun, 12 Feb 2012)");
 script_name("FreeBSD Ports: FreeBSD");


 script_description(desc);

 script_summary("FreeBSD Ports: FreeBSD");

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
bver = portver(pkg:"FreeBSD");
if(!isnull(bver) && revcomp(a:bver, b:"7.3")>=0 && revcomp(a:bver, b:"7.3_7")<0) {
    txt += 'Package FreeBSD version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.4")>=0 && revcomp(a:bver, b:"7.4_3")<0) {
    txt += 'Package FreeBSD version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.1")>=0 && revcomp(a:bver, b:"8.1_5")<0) {
    txt += 'Package FreeBSD version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"8.2")>=0 && revcomp(a:bver, b:"8.2_3")<0) {
    txt += 'Package FreeBSD version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
