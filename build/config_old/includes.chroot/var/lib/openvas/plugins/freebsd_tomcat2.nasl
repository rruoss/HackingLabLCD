#
#VID 4ca26574-2a2c-11e2-99c7-00a0d181e71d
# OpenVAS Vulnerability Test
# $
# Description: Auto generated from VID 4ca26574-2a2c-11e2-99c7-00a0d181e71d
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
tag_insight = "The following package is affected: tomcat

CVE-2012-2733
java/org/apache/coyote/http11/InternalNioInputBuffer.java in the HTTP
NIO connector in Apache Tomcat 6.x before 6.0.36 and 7.x before 7.0.28
does not properly restrict the request-header size, which allows
remote attackers to cause a denial of service (memory consumption) via
a large amount of header data.";
tag_solution = "Update your system with the appropriate patches or
software upgrades.

http://tomcat.apache.org/security.html
http://tomcat.apache.org/security-6.html
http://tomcat.apache.org/security-7.html
http://www.vuxml.org/freebsd/4ca26574-2a2c-11e2-99c7-00a0d181e71d.html";
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
 script_id(72607);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_cve_id("CVE-2012-2733");
 script_tag(name:"risk_factor", value:"Medium");
 script_version("$Revision: 12 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-26 12:47:33 -0500 (Mon, 26 Nov 2012)");
 script_name("FreeBSD Ports: tomcat");

 script_description(desc);

 script_summary("FreeBSD Ports: tomcat");

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
bver = portver(pkg:"tomcat");
if(!isnull(bver) && revcomp(a:bver, b:"6.0.0")>0 && revcomp(a:bver, b:"6.0.36")<0) {
    txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}
if(!isnull(bver) && revcomp(a:bver, b:"7.0.0")>0 && revcomp(a:bver, b:"7.0.28")<0) {
    txt += "Package tomcat version " + bver + " is installed which is known to be vulnerable.\n";
    vuln = 1;
}

if(vuln) {
    security_hole(data:string(txt + "\n" + desc));
} else if (__pkg_match) {
    exit(99);
}
