# OpenVAS Vulnerability Test
# $
# Description: Auto generated from Gentoo's XML based advisory
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
tag_insight = "A memory leak in mod_ssl allows a remote denial of service attack against
an SSL-enabled server via plain HTTP requests. Another flaw was found when
arbitrary client-supplied strings can be written to the error log,
allowing the exploit of certain terminal emulators. A third flaw exists
with the mod_disk_cache module.";
tag_solution = "Users are urged to upgrade to Apache 2.0.49:

    # emerge sync
    # emerge -pv '>=net-www/apache-2.0.49'
    # emerge '>=net-www/apache-2.0.49'

    # ** IMPORTANT **

    # If you are migrating from Apache 2.0.48-r1 or earlier versions,
    # it is important that the following directories are removed.

    # The following commands should cause no data loss since these
    # are symbolic links.

    # rm /etc/apache2/lib /etc/apache2/logs /etc/apache2/modules
    # rm /etc/apache2/extramodules

    # ** ** ** ** **

    # ** ALSO NOTE **

    # Users who use mod_disk_cache should edit their Apache
    # configuration and disable mod_disk_cache.
    

http://www.securityspace.com/smysecure/catid.html?in=GLSA%20200403-04
http://bugs.gentoo.org/show_bug.cgi?id=45206
http://www.securityfocus.com/bid/9933/info/
http://www.apache.org/dist/httpd/Announcement2.html";
tag_summary = "The remote host is missing updates announced in
advisory GLSA 200403-04.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(54529);
 script_cve_id("CVE-2004-0113");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_version("$Revision: 16 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-09-24 21:14:03 +0200 (Wed, 24 Sep 2008)");
 script_tag(name:"risk_factor", value:"Medium");
 script_name("Gentoo Security Advisory GLSA 200403-04 (Apache)");


 script_description(desc);

 script_summary("Gentoo Security Advisory GLSA 200403-04 (Apache)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2005 E-Soft Inc. http://www.securityspace.com");
 script_family("Gentoo Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success", "ssh/login/gentoo");
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

include("pkg-lib-gentoo.inc");

res = "";
report = "";
if ((res = ispkgvuln(pkg:"net-www/apache", unaffected: make_list("eq 1.3*", "ge 2.0.49"), vulnerable: make_list("le 2.0.48"))) != NULL) {
    report += res;
}

if (report != "") {
    security_warning(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
