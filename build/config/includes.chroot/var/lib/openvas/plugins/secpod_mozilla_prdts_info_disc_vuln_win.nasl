###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_info_disc_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Products Information Disclosure Vulnerability (Win)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attackers obtain the mailbox URI of the
  recipient or disclose comments placed in a forwarded email.
  Impact Level: Application";
tag_affected = "Seamonkey version prior to 1.1.13 and
  Thunderbird version prior to 2.0.0.18 on Windows.";
tag_insight = "A flaw exists in the JavaScript code embedded in mailnews which can be
  exploited using scripts which read the '.documentURI' or '.textContent'
  DOM properties.";
tag_solution = "Upgrade to Seamonkey version 1.1.13 or later
  http://www.seamonkey-project.org/releases
  Upgrade to Thunderbird version 2.0.0.18 or later
  http://www.mozillamessaging.com/en-US/thunderbird/all.html";
tag_summary = "The host is installed with Thunderbird/Seamonkey and is prone to
  Information Disclosure vulnerability.";

if(description)
{
  script_id(900910);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-19 06:49:38 +0200 (Wed, 19 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6961");
  script_bugtraq_id(32363);
  script_name("Mozilla Products Information Disclosure Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32714");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32715");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46734");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2008/mfsa2008-59.html");

  script_description(desc);
  script_summary("Check for the version of Thunderbird/Seamonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Seamonkey/Win/Ver", "Thunderbird/Win/Ver");
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

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");

if(smVer != NULL)
{
  # Grep for Seamonkey version prior to 1.1.13
  if(version_is_less(version:smVer, test_version:"1.1.13")){
    security_warning(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");

if(tbVer != NULL)
{
  # Grep for Thunderbird version prior to 2.0.0.18
  if(version_is_less(version:tbVer, test_version:"2.0.0.18")){
    security_warning(0);
  }
}
