# OpenVAS Vulnerability Test
# $Id: mdksa_2009_075.nasl 15 2013-10-27 12:49:54Z jan $
# Description: Auto-generated from advisory MDVSA-2009:075 (firefox)
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
tag_insight = "Security vulnerabilities have been discovered and corrected in
the latest Mozilla Firefox 3.x, version 3.0.7 (CVE-2009-0040,
CVE-2009-0771, CVE-2009-0772, CVE-2009-0773, CVE-2009-0774,
CVE-2009-0775, CVE-2009-0776, CVE-2009-0777).

This update provides the latest Mozilla Firefox 3.x to correct
these issues.

As Mozilla Firefox 2.x has been phased out, version 3.x is also being
provided for Mandriva Linux 2008 Spring.

Additionally some softwares has also been rebuilt against Mozilla
Firefox 3.0.7 which should take care of upgrade problems.

Affected: 2008.1, 2009.0";
tag_solution = "To upgrade automatically use MandrakeUpdate or urpmi.  The verification
of md5 checksums and GPG signatures is performed automatically for you.

https://secure1.securityspace.com/smysecure/catid.html?in=MDVSA-2009:075
http://www.mozilla.org/security/known-vulnerabilities/firefox30.html#firefox3.0.7";
tag_summary = "The remote host is missing an update to firefox
announced via advisory MDVSA-2009:075.";

                                                                                
 desc = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(63587);
 script_version("$Revision: 15 $");
 script_tag(name:"check_type", value:"authenticated package test");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-03-20 00:52:38 +0100 (Fri, 20 Mar 2009)");
 script_cve_id("CVE-2009-0040", "CVE-2009-0771", "CVE-2009-0772", "CVE-2009-0773", "CVE-2009-0774", "CVE-2009-0775", "CVE-2009-0776", "CVE-2009-0777");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Mandrake Security Advisory MDVSA-2009:075 (firefox)");


 script_description(desc);

 script_summary("Mandrake Security Advisory MDVSA-2009:075 (firefox)");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (c) 2009 E-Soft Inc. http://www.securityspace.com");
 script_family("Mandrake Local Security Checks");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("HostDetails/OS/cpe:/o:mandriva:linux", "login/SSH/success", "ssh/login/rpms");
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
if ((res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"devhelp-plugins", rpm:"devhelp-plugins~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.22.3~0.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.22.3~0.4mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ka", rpm:"firefox-ka~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mn", rpm:"firefox-mn~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-oc", rpm:"firefox-oc~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~3.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"galeon", rpm:"galeon~2.0.7~0.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-extras", rpm:"gnome-python-extras~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gda", rpm:"gnome-python-gda~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gda-devel", rpm:"gnome-python-gda-devel~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gdl", rpm:"gnome-python-gdl~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gksu", rpm:"gnome-python-gksu~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkhtml2", rpm:"gnome-python-gtkhtml2~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkmozembed", rpm:"gnome-python-gtkmozembed~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkspell", rpm:"gnome-python-gtkspell~2.19.1~10.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libdevhelp-1_0", rpm:"libdevhelp-1_0~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libdevhelp-1-devel", rpm:"libdevhelp-1-devel~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libgluezilla0", rpm:"libgluezilla0~1.2.6.1~2.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner1.9", rpm:"libxulrunner1.9~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner-devel", rpm:"libxulrunner-devel~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner-unstable-devel", rpm:"libxulrunner-unstable-devel~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-blogrovr", rpm:"mozilla-firefox-ext-blogrovr~1.1.779~2.7mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-foxmarks", rpm:"mozilla-firefox-ext-foxmarks~2.0.47.4~2.7mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-scribefire", rpm:"mozilla-firefox-ext-scribefire~2.2.7~2.7mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"totem", rpm:"totem~2.22.0~4.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"totem-common", rpm:"totem-common~2.22.0~4.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"totem-gstreamer", rpm:"totem-gstreamer~2.22.0~4.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"totem-mozilla", rpm:"totem-mozilla~2.22.0~4.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"totem-mozilla-gstreamer", rpm:"totem-mozilla-gstreamer~2.22.0~4.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.22.1~0.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.22.3~0.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.22.3~0.3mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64devhelp-1_0", rpm:"lib64devhelp-1_0~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64devhelp-1-devel", rpm:"lib64devhelp-1-devel~0.19~3.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64gluezilla0", rpm:"lib64gluezilla0~1.2.6.1~2.9mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner1.9", rpm:"lib64xulrunner1.9~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner-devel", rpm:"lib64xulrunner-devel~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner-unstable-devel", rpm:"lib64xulrunner-unstable-devel~1.9.0.7~0.1mdv2008.1", rls:"MNDK_2008.1")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle", rpm:"beagle~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-crawl-system", rpm:"beagle-crawl-system~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-doc", rpm:"beagle-doc~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-epiphany", rpm:"beagle-epiphany~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-evolution", rpm:"beagle-evolution~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-gui", rpm:"beagle-gui~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-gui-qt", rpm:"beagle-gui-qt~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"beagle-libs", rpm:"beagle-libs~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"devhelp", rpm:"devhelp~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"devhelp-plugins", rpm:"devhelp-plugins~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany", rpm:"epiphany~2.24.0.1~3.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"epiphany-devel", rpm:"epiphany-devel~2.24.0.1~3.6mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox", rpm:"firefox~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ext-beagle", rpm:"firefox-ext-beagle~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ext-mozvoikko", rpm:"firefox-ext-mozvoikko~0.9.5~4.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-fy", rpm:"firefox-fy~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hi", rpm:"firefox-hi~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ka", rpm:"firefox-ka~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ku", rpm:"firefox-ku~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mn", rpm:"firefox-mn~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-oc", rpm:"firefox-oc~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-theme-kde4ff", rpm:"firefox-theme-kde4ff~0.14~4.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~3.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-extras", rpm:"gnome-python-extras~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gda", rpm:"gnome-python-gda~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gda-devel", rpm:"gnome-python-gda-devel~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gdl", rpm:"gnome-python-gdl~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkhtml2", rpm:"gnome-python-gtkhtml2~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkmozembed", rpm:"gnome-python-gtkmozembed~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"gnome-python-gtkspell", rpm:"gnome-python-gtkspell~2.19.1~20.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libdevhelp-1_0", rpm:"libdevhelp-1_0~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libdevhelp-1-devel", rpm:"libdevhelp-1-devel~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner1.9", rpm:"libxulrunner1.9~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner-devel", rpm:"libxulrunner-devel~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"libxulrunner-unstable-devel", rpm:"libxulrunner-unstable-devel~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-blogrovr", rpm:"mozilla-firefox-ext-blogrovr~1.1.779~5.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-foxmarks", rpm:"mozilla-firefox-ext-foxmarks~2.1.0.12~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-firefox-ext-scribefire", rpm:"mozilla-firefox-ext-scribefire~2.3.1~2.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"mozilla-thunderbird-beagle", rpm:"mozilla-thunderbird-beagle~0.3.8~13.7mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"xulrunner", rpm:"xulrunner~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"yelp", rpm:"yelp~2.24.0~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64devhelp-1_0", rpm:"lib64devhelp-1_0~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64devhelp-1-devel", rpm:"lib64devhelp-1-devel~0.21~3.4mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner1.9", rpm:"lib64xulrunner1.9~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner-devel", rpm:"lib64xulrunner-devel~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}
if ((res = isrpmvuln(pkg:"lib64xulrunner-unstable-devel", rpm:"lib64xulrunner-unstable-devel~1.9.0.7~0.1mdv2009.0", rls:"MNDK_2009.0")) != NULL) {
    report += res;
}

if (report != "") {
    security_hole(data:report + '\n' + desc);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
