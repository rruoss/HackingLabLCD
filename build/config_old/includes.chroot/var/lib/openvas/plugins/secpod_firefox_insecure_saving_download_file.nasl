###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_insecure_saving_download_file.nasl 15 2013-10-27 12:49:54Z jan $
#
# Insecure Saving Of Downloadable File In Mozilla Firefox (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Local attackers may leverage this issue by replacing an arbitrary downloaded
  file by placing a file in a /tmp location before the download occurs.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 2.x, 3.x on Linux.";
tag_insight = "This security issue is due to the browser using a fixed path from the
  /tmp directory when a user opens a file downloaded for opening from the
  'Downloads' window. This can be exploited to trick a user into opening a file
  with potentially malicious content by placing it in the /tmp directory before
  the download takes place.";
tag_solution = "Upgrade to Mozilla Firefox version 3.6.3 or later
  For updates refer to http://www.mozilla.com/en-US/firefox/";
tag_summary = "This host is installed with Mozilla Firefox and is prone to insecure
  saving of downloadable file.";

if(description)
{
  script_id(900869);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3274");
  script_name("Insecure Saving Of Downloadable File In Mozilla Firefox (Linux)");
  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36649");
  script_xref(name : "URL" , value : "http://jbrownsec.blogspot.com/2009/09/vamos-updates.html");
  script_xref(name : "URL" , value : "http://securitytube.net/Zero-Day-Demos-%28Firefox-Vulnerability-Discovered%29-video.aspx");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");

# Check for Mozilla Firefox version 2.x or 3.x
if(ffVer =~ "^(2|3)\..*"){
  security_warning(0);
}
