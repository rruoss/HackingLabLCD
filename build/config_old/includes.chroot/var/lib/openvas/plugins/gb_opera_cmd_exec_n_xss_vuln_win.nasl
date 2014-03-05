###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_cmd_exec_n_xss_vuln_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# Opera Web Browser Command Execution and XSS Vulnerabilities (Win)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful remote attack could inject arbitrary HTML and script code,
  launch cross site scripting attacks on user's browser session when malicious
  data is being viewed.
  Impact Level: Application";
tag_affected = "Opera version prior to 9.62 on Windows.";
tag_insight = "Flaws are due to,
  - certain parameters passed to the History Search functionality are not
    properly sanitised before being used.
  - an error exists in the handling of Javascript URLs in the Links panel.";
tag_solution = "Upgrade to Opera 9.62
  http://www.opera.com/download/";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(800048);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-31 15:07:51 +0100 (Fri, 31 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4794", "CVE-2008-4795");
  script_bugtraq_id(31991);
  script_name("Opera Web Browser Command Execution and XSS Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/906/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/907/");

  script_description(desc);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("SMB/WindowsVersion","Opera/Win/Version");
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

operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

if(version_is_less(version:operaVer, test_version:"9.62")){
  security_hole(0);
}
