###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cocsoft_stream_down_bof_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# CoCSoft Stream Down Buffer overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application.
  Impact Level: System/Application";
tag_affected = "CoCSoft Stream Down version 6.8.0";

tag_insight = "The flaw is due to an unspecified error in the application, which can
  be exploited to cause a heap-based buffer overflow.";
tag_solution = "No solution or patch is available as of 2nd January, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cocsoft.com/index.html";
tag_summary = "This host is installed with CoCSoft Stream Down and is prone to
  buffer overflow vulnerability.";

if(description)
{
  script_id(802551);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-5052");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-02 16:06:04 +0530 (Mon, 02 Jan 2012)");
  script_name("CoCSoft Stream Down Buffer overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18283/");
  script_xref(name : "URL" , value : "http://dev.metasploit.com/redmine/issues/6168");

  script_description(desc);
  script_summary("Check for the version of CoCSoft Stream Down");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  cocName = registry_get_sz(key:key + item, item:"DisplayName");

  ## Check DisplayName for CoCSoft StreamDown
  if("StreamDown" >< cocName)
  {
    ## Get CoCSoft StreamDown version
    cocVer = eregmatch(pattern:"[0-9.]+", string:cocName);
    if(cocVer[0]!= NULL)
    {
      ## Check for CoCSoft StreamDown version
      if(version_is_equal(version:cocVer[0], test_version:"6.8.0"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}
