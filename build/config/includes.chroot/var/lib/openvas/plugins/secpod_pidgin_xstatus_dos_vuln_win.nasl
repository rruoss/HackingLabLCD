###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_xstatus_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Pidgin 'X-Status' Message Denial of Service Vulnerability (Win)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users.
  Impact Level: Application";
tag_affected = "Pidgin versions prior to 2.7.2";
tag_insight = "The flaw is caused by a NULL pointer dereference error when processing
  malformed 'X-Status' messages, which could be exploited by attackers to
  crash an affected application, creating a denial of service condition.";
tag_solution = "Upgrade to Pidgin version 2.7.2 or later,
  For updates refer to http://pidgin.im/download/windows/";
tag_summary = "This host is installed with Pidgin and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(901137);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41881);
  script_cve_id("CVE-2010-2528");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Pidgin 'X-Status' Message Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40699");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60566");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1887");
  script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/index.php?id=47");

  script_description(desc);
  script_summary("Check for the Version of Pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_pidgin_detect_win.nasl");
  script_require_keys("Pidgin/Win/Ver");
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

## Get Pidgin Version from KB
pidginVer = get_kb_item("Pidgin/Win/Ver");

if(pidginVer != NULL)
{
  ## Check for Pidgin Versions Prior to 2.7.2
  if(version_is_less(version:pidginVer, test_version:"2.7.2")){
    security_warning(0);
  }
}

