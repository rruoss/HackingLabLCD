# OpenVAS Vulnerability Test
# $Id: fcore_2009_8288.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory FEDORA-2009-8288 (perl-Gtk2-MozEmbed)
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
tag_insight = "This module allows you to use the Mozilla embedding widget from Perl.

Update Information:

Update to new upstream Firefox version 3.0.13, fixing multiple security issues
detailed in the upstream advisories:
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.13

Update also includes all packages depending on gecko-libs rebuilt against
new version of Firefox / XULRunner.

Note: Issues described in MFSA 2009-42 and MFSA 2009-43 were
previously addressed via rebase of the NSS packages.";
tag_solution = "Apply the appropriate updates.

This update can be installed with the yum update program.  Use 
su -c 'yum update perl-Gtk2-MozEmbed' at the command line.
For more information, refer to Managing Software with yum,
available at http://docs.fedoraproject.org/yum/.

https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-8288";
tag_summary = "The remote host is missing an update to perl-Gtk2-MozEmbed
announced via advisory FEDORA-2009-8288.";


 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(64554);
 script_cve_id("CVE-2009-2470","CVE-2009-2654","CVE-2009-2662","CVE-2009-2663","CVE-2009-2664","CVE-2009-2665");
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-08-17 16:54:45 +0200 (Mon, 17 Aug 2009)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Fedora Core 10 FEDORA-2009-8288 (perl-Gtk2-MozEmbed)");


 script_description(desc);

 script_summary("Fedora Core 10 FEDORA-2009-8288 (perl-Gtk2-MozEmbed)");

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
 exit(0);
}

#
# The script code starts here
#

include("pkg-lib-rpm.inc");

res = "";
report = "";
if ((res = isrpmvuln(pkg:"perl-Gtk2-MozEmbed", rpm:"perl-Gtk2-MozEmbed~0.08~6.fc10.4", rls:"FC10")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"perl-Gtk2-MozEmbed", rpm:"perl-Gtk2-MozEmbed~debuginfo~0.08", rls:"FC10")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
