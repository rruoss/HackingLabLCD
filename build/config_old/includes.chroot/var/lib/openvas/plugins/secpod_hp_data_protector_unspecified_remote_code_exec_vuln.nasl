###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_data_protector_unspecified_remote_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP OpenView Storage Data Protector Unspecified Remote Code Execution Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_solution = "Apply the patch,
  http://support.openview.hp.com/selfsolve/patches

  *****
  NOTE : Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application.
  Impact Level: System/Application.";
tag_affected = "HP OpenView Storage Data Protector versions 6.0, 6.10, and 6.11";
tag_insight = "The flaw is caused by an unspecified error, which allows remote attackers to
  execute arbitrary code via unknown vectors.";
tag_summary = "This host is running HP OpenView Storage Data Protector and
  is prone to remote code execution vulnerability.";

if(description)
{
  script_id(902531);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-1864");
  script_bugtraq_id(48178);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("HP OpenView Storage Data Protector Unspecified Remote Code Execution Vulnerability");
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

  script_xref(name : "URL" , value : "http://www.itrc.hp.com/service/cki/docDisplay.do?docId=emr_na-c02712867");

  script_description(desc);
  script_summary("Check for the version of HP OpenView Storage Data Protector");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_keys("Services/data_protector/version");
  script_require_ports(5555);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## HP Data Protector default port
port = 5555;
if(!get_port_state(port)){
  exit(0);
}

## Get version from KB
hdpmVer = get_kb_item("Services/data_protector/version");
if(hdpmVer)
{
  ver = eregmatch(pattern:"([a-zA-z]\.)([0-9.]+)", string: hdpmVer);
  if(ver[2])
  {
    ## Check for HP OpenView Storage Data Protector versions 6.0, 6.10, and 6.11
    if(version_is_equal(version:ver[2], test_version:"06.0") ||
       version_is_equal(version:ver[2], test_version:"06.10")||
       version_is_equal(version:ver[2], test_version:"06.11")){
      security_hole(port:port);
    }
  }
}
