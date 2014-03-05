###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pipi_player_activex_ctrl_bof_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# PIPI Player PIPIWebPlayer ActiveX Control Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  Impact Level: Application.";
tag_affected = "PIPI Player version 2.8.0.0";

tag_insight = "The flaw is due to an error when processing the 'PlayURL()' and
  'PlayURLWithLocalPlayer()' methods. This can be exploited to cause a
  stack-based buffer overflow via an overly long string passed to the methods.";
tag_solution = "No solution or patch is available as of 28th Febraury, 2011. Information
  regarding this issue will update once the solution details are available.
  For updates refer to http://pipi.cn/down/index.html";
tag_summary = "This host is installed with PIPI Player and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(902346);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-04 14:32:35 +0100 (Fri, 04 Mar 2011)");
  script_cve_id("CVE-2011-1065");
  script_bugtraq_id(46468);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("PIPI Player PIPIWebPlayer ActiveX Control Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43394");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65537");
  script_xref(name : "URL" , value : "http://www.wooyun.org/bugs/wooyun-2010-01383");

  script_description(desc);
  script_summary("Check for the version of PIPI Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

if(!registry_key_exists(key:key)) {
    exit(0);
}

## Get Install Location From Registry
foreach item (registry_enum_keys(key:key))
{
  name = registry_get_sz(key:key + item, item:"DisplayName");
  if("PIPI" >< name)
  {
    ver = eregmatch(pattern:"PIPI ([0-9.]+)", string:name);
    if(ver[1] != NULL)
    {
      ## Check for PIPI Player version equal to 2.8.0.0
      if(version_is_equal(version:ver[1], test_version:"2.8.0.0")){
        security_hole(0) ;
      }
    }
  }
}
