###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_ie_li_element_dos_vuln_sep09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer 'li' Element DoS Vulnerability - Sep09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attackers can cause the application
  to crash.
  Impact Level: Application";
tag_affected = "Microsoft, Internet Explorer version 6.x on Windows XP SP2/SP3";
tag_insight = "Error exists when application fails to handle a crafted JavaScript code, that
  calls 'createElement' to create an instance of the 'li' element, and then
  calls 'setAttribute' to set the value attribute.";
tag_solution = "Upgrade to Internet Explorer version 8 or 8 beta 2
  http://www.microsoft.com/windows/internet-explorer/default.aspx";
tag_summary = "This host has Internet Explorer installed and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(800872);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3019");
  script_bugtraq_id(36070);
  script_name("Microsoft Internet Explorer 'li' Element DoS Vulnerability - Sep09");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9455");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/36070-1.html");
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/36070-3.txt");
  script_xref(name : "URL" , value : "https://connect.microsoft.com/IE/feedback/ViewFeedback.aspx?FeedbackID=338599");

  script_description(desc);
  script_summary("Check for the Version of Internet Explorer");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");

# Check for XP SP3
SP = get_kb_item("SMB/WinXP/ServicePack");
if(("Service Pack 3" >< SP) || ("Service Pack 2" >< SP))
{
  # Get for Internet Explorer Version
  ieVer = get_kb_item("MS/IE/Version");
  # Check for IE 6
  if(ieVer =~ "^6\..*"){
    security_warning(0);
  }
}
