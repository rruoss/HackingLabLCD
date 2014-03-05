#
#VID 6c8ad3e8-0a30-11e1-9580-4061862b8c22
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 6c8ad3e8-0a30-11e1-9580-4061862b8c22
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
tag_insight = "The following packages are affected:
   firefox
   libxul
   linux-firefox
   linux-thunderbird
   thunderbird

CVE-2011-3647
The JSSubScriptLoader in Mozilla Firefox before 3.6.24 and Thunderbird
before 3.1.6 does not properly handle XPCNativeWrappers during calls
to the loadSubScript method in an add-on, which makes it easier for
remote attackers to gain privileges via a crafted web site that
leverages certain unwrapping behavior, a related issue to
CVE-2011-3004.

CVE-2011-3648
Cross-site scripting (XSS) vulnerability in Mozilla Firefox before
3.6.24 and 4.x through 7.0 and Thunderbird before 3.1.6 and 5.0
through 7.0 allows remote attackers to inject arbitrary web script or
HTML via crafted text with Shift JIS encoding.

CVE-2011-3649
Mozilla Firefox 7.0 and Thunderbird 7.0, when the Direct2D (aka D2D)
API is used on Windows in conjunction with the Azure graphics
back-end, allow remote attackers to bypass the Same Origin Policy, and
obtain sensitive image data from a different domain, by inserting this
data into a canvas.  NOTE: this issue exists because of a CVE-2011-2986
regression.

CVE-2011-3650
Mozilla Firefox before 3.6.24 and 4.x through 7.0 and Thunderbird
before 3.1.6 and 5.0 through 7.0 do not properly handle JavaScript
files that contain many functions, which allows user-assisted remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly have unspecified other impact via a
crafted file that is accessed by debugging APIs, as demonstrated by
Firebug.

CVE-2011-3651
Multiple unspecified vulnerabilities in the browser engine in Mozilla
Firefox 7.0 and Thunderbird 7.0 allow remote attackers to cause a
denial of service (memory corruption and application crash) or
possibly execute arbitrary code via unknown vectors.

CVE-2011-3652
The browser engine in Mozilla Firefox before 8.0 and Thunderbird
before 8.0 does not properly allocate memory, which allows remote
attackers to cause a denial of service (memory corruption and
application crash) or possibly execute arbitrary code via unspecified
vectors.

CVE-2011-3653
Mozilla Firefox before 8.0 and Thunderbird before 8.0 on Mac OS X do
not properly interact with the GPU memory behavior of a certain driver
for Intel integrated GPUs, which allows remote attackers to bypass the
Same Origin Policy and read image data via vectors related to WebGL
textures.

CVE-2011-3654
The browser engine in Mozilla Firefox before 8.0 and Thunderbird
before 8.0 does not properly handle links from SVG mpath elements to
non-SVG elements, which allows remote attackers to cause a denial of
service (memory corruption and application crash) or possibly execute
arbitrary code via unspecified vectors.

CVE-2011-3655
Mozilla Firefox 4.x through 7.0 and Thunderbird 5.0 through 7.0
perform access control without checking for use of the NoWaiverWrapper
wrapper, which allows remote attackers to gain privileges via a
crafted web site.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://www.mozilla.org/security/announce/2011/mfsa2011-46.html
http://www.mozilla.org/security/announce/2011/mfsa2011-47.html
http://www.mozilla.org/security/announce/2011/mfsa2011-48.html
http://www.mozilla.org/security/announce/2011/mfsa2011-49.html
http://www.mozilla.org/security/announce/2011/mfsa2011-50.html
http://www.mozilla.org/security/announce/2011/mfsa2011-51.html
http://www.mozilla.org/security/announce/2011/mfsa2011-52.html
http://www.vuxml.org/freebsd/6c8ad3e8-0a30-11e1-9580-4061862b8c22.html";
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
 script_id(70609);
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3649", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3653", "CVE-2011-3654", "CVE-2011-3655");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 18 $");
 script_name("FreeBSD Ports: firefox");


 script_description(desc);

 script_summary("FreeBSD Ports: firefox");

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
bver = portver(pkg:"firefox");
if(!isnull(bver) && revcomp(a:bver, b:"4.0,1")>0 && revcomp(a:bver, b:"8.0,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.6.*,1")>0 && revcomp(a:bver, b:"3.6.24,1")<0) {
    txt += 'Package firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"libxul");
if(!isnull(bver) && revcomp(a:bver, b:"1.9.2")>0 && revcomp(a:bver, b:"1.9.2.24")<0) {
    txt += 'Package libxul version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-firefox");
if(!isnull(bver) && revcomp(a:bver, b:"8.0,1")<0) {
    txt += 'Package linux-firefox version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"linux-thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"8.0")<0) {
    txt += 'Package linux-thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
bver = portver(pkg:"thunderbird");
if(!isnull(bver) && revcomp(a:bver, b:"4.0")>0 && revcomp(a:bver, b:"8.0")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"3.1.16")<0) {
    txt += 'Package thunderbird version ' + bver + ' is installed which is known to be vulnerable.\n';
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt, "\n", desc));
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
