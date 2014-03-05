#
#VID b206dd82-ac67-11d9-a788-0001020eed82
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
   openoffice ar-openoffice ca-openoffice cs-openoffice de-openoffice
   dk-openoffice el-openoffice es-openoffice et-openoffice fi-openoffice
   fr-openoffice gr-openoffice hu-openoffice it-openoffice ja-openoffice
   ko-openoffice nl-openoffice pl-openoffice pt-openoffice pt_BR-openoffice
   ru-openoffice se-openoffice sk-openoffice sl-openoffice-SI tr-openoffice
   zh-openoffice-CN zh-openoffice-TW jp-openoffice kr-openoffice
   sl-openoffice-SL zh-openoffice zh_TW-openoffice

CVE-2005-0941
The StgCompObjStream::Load function in OpenOffice.org OpenOffice 1.1.4
and earlier allocates memory based on 16 bit length values, but
process memory using 32 bit values, which allows remote attackers to
cause a denial of service and possibly execute arbitrary code via a
DOC document with certain length values, which leads to a heap-based
buffer overflow.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.openoffice.org/issues/show_bug.cgi?id=46388
http://marc.theaimsgroup.com/?l=bugtraq&m=111325305109137
http://www.vuxml.org/freebsd/b206dd82-ac67-11d9-a788-0001020eed82.html";
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
 script_id(52138);
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-04 20:41:11 +0200 (Thu, 04 Sep 2008)");
 script_cve_id("CVE-2005-0941");
 script_bugtraq_id(13092);
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("openoffice -- DOC document heap overflow vulnerability");


 script_description(desc);

 script_summary("openoffice -- DOC document heap overflow vulnerability");

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
bver = portver(pkg:"openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ar-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package ar-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ca-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package ca-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"cs-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package cs-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"de-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package de-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"dk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package dk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"el-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package el-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"es-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package es-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"et-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package et-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fi-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package fi-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"fr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package fr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"gr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package gr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"hu-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package hu-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"it-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package it-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ko-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package ko-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"nl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package nl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pl-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package pl-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package pt-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"pt_BR-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package pt_BR-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ru-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package ru-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"se-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package se-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sk-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package sk-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sl-openoffice-SI");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package sl-openoffice-SI version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"tr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package tr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-openoffice-CN");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package zh-openoffice-CN version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-openoffice-TW");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package zh-openoffice-TW version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"jp-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package jp-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package jp-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"kr-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package kr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package kr-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"sl-openoffice-SL");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package sl-openoffice-SL version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package sl-openoffice-SL version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package zh-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package zh-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"zh_TW-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"1.1.4_2")<0) {
    txt += 'Package zh_TW-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"2")>0 && revcomp(a:bver, b:"2.0.20050406")<=0) {
    txt += 'Package zh_TW-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.a609")>=0 && revcomp(a:bver, b:"6.0.a638")<=0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"641c")>=0 && revcomp(a:bver, b:"645")<=0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1RC4")==0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1rc5")==0) {
    txt += 'Package openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"ja-openoffice");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.a609")>=0 && revcomp(a:bver, b:"6.0.a638")<=0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"641c")>=0 && revcomp(a:bver, b:"645")<=0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1RC4")==0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"1.1rc5")==0) {
    txt += 'Package ja-openoffice version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
