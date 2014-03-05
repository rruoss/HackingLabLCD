# OpenVAS Vulnerability Test
# $Id: fcore_2009_3357.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-3357 (mapserver)
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
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
tag_insight = "Update Information:

The releases contain fixes for issues discovered in an audit of the
CGI by a 3rd party  (tickets #2939, #2941, #2942, #2943 and #2944).
The issues are detailed at:
http://trac.osgeo.org/mapserver/ticket/2939
http://trac.osgeo.org/mapserver/ticket/2941
http://trac.osgeo.org/mapserver/ticket/2942
http://trac.osgeo.org/mapserver/ticket/2943
http://trac.osgeo.org/mapserver/ticket/2944

Also provided is support for RFC-56 that addresses tightening up the
control of access to mapfiles and templates:
http://mapserver.org/development/rfc/ms-rfc-56.html

ChangeLog:

* Sun Apr  5 2009 Devrim GUNDUZ  - 5.2.2-1
- Update to 5.2.2 which fixes :
CVE-2009-0839, CVE-2009-0840, CVE-2009-0841, CVE-2009-0842,
CVE-2009-0843, CVE-2009-1176, CVE-2009-1177.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update mapserver' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-3357";
tag_summary = "The remote host is missing an update to mapserver
announced via advisory FEDORA-2009-3357.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63771);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-04-15 22:11:00 +0200 (Wed, 15 Apr 2009)");
 script_cve_id("CVE-2009-0839", "CVE-2009-0840", "CVE-2009-0841", "CVE-2009-0842", "CVE-2009-0843", "CVE-2009-1176", "CVE-2009-1177");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-3357 (mapserver)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-3357 (mapserver)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Fedora Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:fedoraproject:fedora", "login/SSH/success", "ssh/login/rpms");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=493364");
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"mapserver", rpm:"mapserver~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mapserver-java", rpm:"mapserver-java~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mapserver-perl", rpm:"mapserver-perl~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mapserver-python", rpm:"mapserver-python~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"php-mapserver", rpm:"php-mapserver~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mapserver-debuginfo", rpm:"mapserver-debuginfo~5.2.2~1.fc10", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
