###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_web_server_dir_trav_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# VMware 2 Web Server Directory Traversal Vulnerability (Win)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to disclose sensitive
  information.
  Impact Level: Application/System";
tag_affected = "VMware Web Server Version 2.0.2";
tag_insight = "The flaw is due to an error while handling certain requests, which
  can be exploited to download arbitrary files from the host system.";
tag_solution = "No solution or patch is available as of 3rd December 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.vmware.com/products/server/";
tag_summary = "This host is installed with VMware 2 Web Server and is prone to
  directory traversal vulnerability.";

if(description)
{
  script_id(801654);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("VMware 2 Web Server Directory Traversal Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15617/");
  script_xref(name : "URL" , value : "http://www.vul.kr/vmware-2-web-server-directory-traversal");

  script_description(desc);
  script_summary("Check for the version of VMware Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_vmware_prdts_detect_win.nasl");
  script_require_keys("VMware/Server/Win/Ver", "VMware/Win/Installed");
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

## Check for VMware Installed
if(!get_kb_item("VMware/Win/Installed")){
  exit(0);
}

## Get VMware Server Version
vmserVer = get_kb_item("VMware/Server/Win/Ver");
if(vmserVer)
{
  if(version_is_equal(version:vmserVer, test_version:"2.0.2")){
    security_warning(0);
  }
}
