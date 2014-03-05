###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_data_protector_manager_dos_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# HP Data Protector Manager Remote Denial of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to cause denial of service
  condition.
  Impact Level: Application.";
tag_affected = "HP Data Protector Manager 6.11";
tag_insight = "The flaw is caused by an error in the RDS service (rds.exe) when processing
  malformed packets sent to port 1530/TCP, which could be exploited by remote
  attackers to crash an affected server.";
tag_solution = "No solution or patch is available as of 24th january, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://h71028.www7.hp.com/enterprise/w1/en/software/information-management-data-protector.html";
tag_summary = "This host is installed with HP Data Protector Manager and is prone
  to denial of service vulnerability.";

if(description)
{
  script_id(801579);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2011-0514");
  script_name("HP Data Protector Manager Remote Denial of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15940/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0064");

  script_description(desc);
  script_summary("Check for the version of HP Data Protector Manager");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("hp_data_protector_installed.nasl");
  script_require_keys("Services/data_protector/version");
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

port = 5555;
if(!get_port_state(port)){
  exit(0);
}

## Get the version from KB
hdpmVer = get_kb_item("Services/data_protector/version");
if(hdpmVer)
{
  ver = eregmatch(pattern:"([a-zA-z]\.)([0-9.]+)", string: hdpmVer);
  if(ver[2])
  {
    ## check the version equal to 06.11
    if(version_is_equal(version:ver[2], test_version:"06.11")){
      security_warning(port:port);
    }
  }
}
