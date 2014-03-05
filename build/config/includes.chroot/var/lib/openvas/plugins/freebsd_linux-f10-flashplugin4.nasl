#
#VID 4b8b748e-2a24-11e2-bb44-003067b2972c
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 4b8b748e-2a24-11e2-bb44-003067b2972c
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
tag_insight = "The following package is affected: linux-f10-flashplugin

CVE-2012-5274
Buffer overflow in Adobe Flash Player before 10.3.183.43 and 11.x
before 11.5.502.110 on Windows and Mac OS X, before 10.3.183.43 and
11.x before 11.2.202.251 on Linux, before 11.1.111.24 on Android 2.x
and 3.x, and before 11.1.115.27 on Android 4.x; Adobe AIR before
3.5.0.600; and Adobe AIR SDK before 3.5.0.600 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2012-5275, CVE-2012-5276, CVE-2012-5277, and
CVE-2012-5280.
CVE-2012-5275
Buffer overflow in Adobe Flash Player before 10.3.183.43 and 11.x
before 11.5.502.110 on Windows and Mac OS X, before 10.3.183.43 and
11.x before 11.2.202.251 on Linux, before 11.1.111.24 on Android 2.x
and 3.x, and before 11.1.115.27 on Android 4.x; Adobe AIR before
3.5.0.600; and Adobe AIR SDK before 3.5.0.600 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2012-5274, CVE-2012-5276, CVE-2012-5277, and
CVE-2012-5280.
CVE-2012-5276
Buffer overflow in Adobe Flash Player before 10.3.183.43 and 11.x
before 11.5.502.110 on Windows and Mac OS X, before 10.3.183.43 and
11.x before 11.2.202.251 on Linux, before 11.1.111.24 on Android 2.x
and 3.x, and before 11.1.115.27 on Android 4.x; Adobe AIR before
3.5.0.600; and Adobe AIR SDK before 3.5.0.600 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2012-5274, CVE-2012-5275, CVE-2012-5277, and
CVE-2012-5280.
CVE-2012-5277
Buffer overflow in Adobe Flash Player before 10.3.183.43 and 11.x
before 11.5.502.110 on Windows and Mac OS X, before 10.3.183.43 and
11.x before 11.2.202.251 on Linux, before 11.1.111.24 on Android 2.x
and 3.x, and before 11.1.115.27 on Android 4.x; Adobe AIR before
3.5.0.600; and Adobe AIR SDK before 3.5.0.600 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2012-5274, CVE-2012-5275, CVE-2012-5276, and
CVE-2012-5280.
CVE-2012-5278
Adobe Flash Player before 10.3.183.43 and 11.x before 11.5.502.110 on
Windows and Mac OS X, before 10.3.183.43 and 11.x before 11.2.202.251
on Linux, before 11.1.111.24 on Android 2.x and 3.x, and before
11.1.115.27 on Android 4.x; Adobe AIR before 3.5.0.600; and Adobe AIR
SDK before 3.5.0.600 allow attackers to bypass intended access
restrictions and execute arbitrary code via unspecified vectors.
CVE-2012-5279
Adobe Flash Player before 10.3.183.43 and 11.x before 11.5.502.110 on
Windows and Mac OS X, before 10.3.183.43 and 11.x before 11.2.202.251
on Linux, before 11.1.111.24 on Android 2.x and 3.x, and before
11.1.115.27 on Android 4.x; Adobe AIR before 3.5.0.600; and Adobe AIR
SDK before 3.5.0.600 allow attackers to execute arbitrary code or
cause a denial of service (memory corruption) via unspecified vectors.
CVE-2012-5280
Buffer overflow in Adobe Flash Player before 10.3.183.43 and 11.x
before 11.5.502.110 on Windows and Mac OS X, before 10.3.183.43 and
11.x before 11.2.202.251 on Linux, before 11.1.111.24 on Android 2.x
and 3.x, and before 11.1.115.27 on Android 4.x; Adobe AIR before
3.5.0.600; and Adobe AIR SDK before 3.5.0.600 allows attackers to
execute arbitrary code via unspecified vectors, a different
vulnerability than CVE-2012-5274, CVE-2012-5275, CVE-2012-5276, and
CVE-2012-5277.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

https://www.adobe.com/support/security/bulletins/apsb12-24.html
http://www.vuxml.org/freebsd/4b8b748e-2a24-11e2-bb44-003067b2972c.html";
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
 script_id(72608);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277", "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280");
 script_tag(name:"risk_factor", value:"Critical");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
 script_name("FreeBSD Ports: linux-f10-flashplugin");

 script_description(desc);

 script_summary("FreeBSD Ports: linux-f10-flashplugin");

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
bver = portver(pkg:"linux-f10-flashplugin");
if(!isnull(bver) && revcomp(a:bver, b:"11.2r202.243")<=0) {
    txt += "Package linux-f10-flashplugin version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99);
}
