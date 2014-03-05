###############################################################################
# OpenVAS Vulnerability Test
#
# SuSE Update for Chromium openSUSE-SU-2012:1637-1 (Chromium)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "Chromium was updated to 25.0.1343

  * Security Fixes (bnc#791234 and bnc#792154):
  - CVE-2012-5131: Corrupt rendering in the Apple OSX
  driver for Intel GPUs
  - CVE-2012-5133: Use-after-free in SVG filters.
  - CVE-2012-5130: Out-of-bounds read in Skia
  - CVE-2012-5132: Browser crash with chunked encoding
  - CVE-2012-5134: Buffer underflow in libxml.
  - CVE-2012-5135: Use-after-free with printing.
  - CVE-2012-5136: Bad cast in input element handling.
  - CVE-2012-5138: Incorrect file path handling
  - CVE-2012-5137: Use-after-free in media source handling

  - Correct build so that proprietary codecs can be used when
  the chromium-ffmpeg package is installed

  - Update to 25.0.1335
  * {gtk} Fixed &lt;input&gt; selection renders white text on
  white background in apps. (Issue: 158422)
  * Fixed translate infobar button to show selected
  language. (Issue: 155350)
  * Fixed broken Arabic language. (Issue: 158978)
  * Fixed pre-rendering if the preference is disabled at
  start up. (Issue: 159393)
  * Fixed JavaScript rendering issue. (Issue: 159655)
  * No further indications in the ChangeLog
  * Updated V8 - 3.14.5.0
  * Bookmarks are now searched by their title while typing
  into the omnibox with matching bookmarks being shown in
  the autocomplete suggestions pop-down list. Matching is
  done by prefix.
  * Fixed chromium issues 155871, 154173, 155133.

  - Removed patch chomium-ffmpeg-no-pkgconfig.patch
  - Building now internal libffmpegsumo.so based on the
  standard chromium ffmpeg codecs
  - Add a configuration file (/etc/default/chromium) where we
  can indicate flags for the chromium-browser.
  - add explicit buildrequire on libbz2-devel";

tag_affected = "Chromium on openSUSE 12.1";
tag_solution = "Please Install the Updated Packages.";

  desc = "

  Vulnerability Insight:
  " + tag_insight + "
  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;


if(description)
{
  script_xref(name : "URL" , value : "http://195.135.221.135/opensuse-security-announce/2012-12/msg00004.html");
  script_id(850379);
  script_version("$Revision: 12 $");
  script_tag(name:"check_type", value:"authenticated package test");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-14 09:52:50 +0530 (Fri, 14 Dec 2012)");
  script_cve_id("CVE-2012-5130", "CVE-2012-5131", "CVE-2012-5132", "CVE-2012-5133",
                "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137",
                "CVE-2012-5138");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_xref(name: "openSUSE-SU", value: "2012:1637_1");
  script_name("SuSE Update for Chromium openSUSE-SU-2012:1637-1 (Chromium)");

  script_description(desc);
  script_summary("Check for the Version of Chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("HostDetails/OS/cpe:/o:novell:opensuse", "login/SSH/success", "ssh/login/release");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
  }
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium", rpm:"chromium~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-gnome", rpm:"chromium-desktop-gnome~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-desktop-kde", rpm:"chromium-desktop-kde~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo", rpm:"chromium-ffmpegsumo~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-ffmpegsumo-debuginfo", rpm:"chromium-ffmpegsumo-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper", rpm:"chromium-suid-helper~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"chromium-suid-helper-debuginfo", rpm:"chromium-suid-helper-debuginfo~25.0.1343.0~1.43.1", rls:"openSUSE12.1")) != NULL)
  {
    security_hole(data:res + '\n' + desc);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
