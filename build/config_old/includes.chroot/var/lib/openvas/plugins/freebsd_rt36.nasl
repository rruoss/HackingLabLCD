#
#VID bf171509-68dd-11e0-afe6-0003ba02bf30
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID bf171509-68dd-11e0-afe6-0003ba02bf30
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com
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
   rt36
   rt38

CVE-2011-1685
Best Practical Solutions RT 3.8.0 through 3.8.9 and 4.0.0rc through
4.0.0rc7, when the CustomFieldValuesSources (aka external custom
field) option is enabled, allows remote authenticated users to execute
arbitrary code via unspecified vectors, as demonstrated by a
cross-site request forgery (CSRF) attack.

CVE-2011-1686
Multiple SQL injection vulnerabilities in Best Practical Solutions RT
2.0.0 through 3.6.10, 3.8.0 through 3.8.9, and 4.0.0rc through
4.0.0rc7 allow remote authenticated users to execute arbitrary SQL
commands via unspecified vectors, as demonstrated by reading data.

CVE-2011-1687
Best Practical Solutions RT 3.0.0 through 3.6.10, 3.8.0 through 3.8.9,
and 4.0.0rc through 4.0.0rc7 allows remote authenticated users to
obtain sensitive information by using the search interface, as
demonstrated by retrieving encrypted passwords.

CVE-2011-1688
Directory traversal vulnerability in Best Practical Solutions RT 3.2.0
through 3.6.10, 3.8.0 through 3.8.9, and 4.0.0rc through 4.0.0rc7
allows remote attackers to read arbitrary files via a crafted HTTP
request.

CVE-2011-1689
Multiple cross-site scripting (XSS) vulnerabilities in Best Practical
Solutions RT 2.0.0 through 3.6.10, 3.8.0 through 3.8.9, and 4.0.0rc
through 4.0.0rc7 allow remote attackers to inject arbitrary web script
or HTML via unspecified vectors.

CVE-2011-1690
Best Practical Solutions RT 3.6.0 through 3.6.10 and 3.8.0 through
3.8.8 allows remote attackers to trick users into sending credentials
to an arbitrary server via unspecified vectors.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://secunia.com/advisories/44189
http://www.vuxml.org/freebsd/bf171509-68dd-11e0-afe6-0003ba02bf30.html";
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
 script_id(69594);
 script_version("$Revision: 13 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-05-12 19:21:50 +0200 (Thu, 12 May 2011)");
 script_tag(name:"cvss_base", value:"6.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
 script_cve_id("CVE-2011-1685", "CVE-2011-1686", "CVE-2011-1687", "CVE-2011-1688", "CVE-2011-1689", "CVE-2011-1690");
 script_tag(name:"risk_factor", value:"High");
 script_name("FreeBSD Ports: rt36");


 script_description(desc);

 script_summary("FreeBSD Ports: rt36");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com");
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
bver = portver(pkg:"rt36");
if(!isnull(bver) && revcomp(a:bver, b:"3.6.11")<0) {
    txt += 'Package rt36 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"rt38");
if(!isnull(bver) && revcomp(a:bver, b:"3.8.10")<0) {
    txt += 'Package rt38 version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
