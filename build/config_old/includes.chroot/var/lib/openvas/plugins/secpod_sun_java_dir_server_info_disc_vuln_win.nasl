###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_java_dir_server_info_disc_vuln_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Sun Java Directory Server Information Disclosure Vulnerability (Win)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and can gain sensitive information about the
  presence of folders and files.

  Impact level: Application";

tag_affected = "Sun Java System Directory Server 5.2
  Sun Java System Directory Server Enterprise 5.0";
tag_insight = "This flaw is due to unspecified error which can be exploited to determine
  the existence of a file on a system and disclose a single line of the file's
  content.";
tag_solution = "Upgrade to Sun Java Directory Server Enterprise 6.0 or later
  http://www.sun.com/software/products/directory_srvr_ee/get.jsp";
tag_summary = "This host is running Sun Java Directory Server and is prone to Information
  Disclosure Vulnerability.";

if(description)
{
  script_id(900497);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-1332");
  script_bugtraq_id(34548);
  script_name("Sun Java Directory Server Information Disclosure Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34751");
  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-66-255848-1");

  script_description(desc);
  script_summary("Check for the version of Java Directory Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_sun_java_dir_server_detect_win.nasl");
  script_require_keys("Sun/JavaDirServer/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

appVer = get_kb_item("Sun/JavaDirServer/Win/Ver");
if(!appVer){
  exit(0);
}

# Grep for Directory Server version 5.2 or 5.0
if(version_is_less_equal(version:appVer, test_version:"5.2")){
  security_warning(0);
}
