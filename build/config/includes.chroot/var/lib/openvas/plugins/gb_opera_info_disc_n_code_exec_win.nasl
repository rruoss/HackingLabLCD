###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_info_disc_n_code_exec_win.nasl 16 2013-10-27 13:09:52Z jan $
#
# Opera Remote Code Execution and Information Disclosure Vulnerabilities (Win)
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
tag_impact = "Successful remote attack could inject arbitrary code, launch
  cross site attacks, information disclosure and can even steal related DB
  (DataBase) contents.
  Impact Level: Application";
tag_affected = "Opera version prior to 9.60 on Windows.";
tag_insight = "Flaws are due to,
  - an error in Opera.dll, that fails to anchor identifier (optional argument)
  - an unknown error in predicting the cache pathname of a cached Java
    applet and then launching this applet from the cache.";
tag_solution = "Upgrade to Opera 9.60 or later
  http://www.opera.com/download/";
tag_summary = "The host is installed with Opera Web Browser and is prone to
  remote code execution and information disclosure Vulnerabilities.";

if(description)
{
  script_id(800046);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-30 06:53:04 +0100 (Thu, 30 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4694", "CVE-2008-4695");
  script_name("Opera Remote Code Execution and Information Disclosure Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/901/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/902/");

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

if(version_is_less(version:operaVer, test_version:"9.60")){
  security_hole(0);
}
