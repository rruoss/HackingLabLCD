###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_diag_srv_msg_pkt_bof_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# HP Diagnostics Server Message Packet Buffer Overflow Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply vendor supplied patch from below link,
  http://support.openview.hp.com/selfsolve/document/FID/DOCUMENTUM_DIAGSRV_00051

  *****
  NOTE: Ignore this warning if above mentioned patch is installed.
  *****";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition.
  Impact Level: System/Application";

tag_affected = "HP Diagnostics Server 8.x through 8.07 and 9.x through 9.21";
tag_insight = "The flaw is due to an error within the magentservice.exe process when
  parsing crafted message packets sent to TCP port 23472.";
tag_summary = "This host is running HP Diagnostics Server and is prone to
  stack based buffer overflow vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802053";
CPE = "cpe:/a:hp:diagnostics_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_bugtraq_id(55159);
  script_cve_id("CVE-2012-3278");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-22 13:07:18 +0530 (Wed, 22 May 2013)");
  script_name("HP Diagnostics Server Message Packet Buffer Overflow Vulnerability");
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

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/89569");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50325");
  script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-162");
  script_xref(name : "URL" , value : "https://h20566.www2.hp.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c03645497");
  script_summary("Check for the vulnerable version of HP Diagnostics Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_hp_diagnostics_server_detect.nasl");
  script_require_ports("Services/www", 2006, 23472);
  script_mandatory_keys("hpdiagnosticsserver/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

## management port
hpds_port = 0;
hpds_ver = NULL;
hp_mgmt_port = 23472;

## HP Diagnostics Server and magentservice port
## Get HTTP Port
if(!hpds_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  hpds_port = 2006;
}

## check hp http and management port are up or not
if(!get_port_state(hpds_port) || !get_port_state(hp_mgmt_port)){
  exit(0);
}

## Get Version from KB
hpds_ver = get_kb_item("www/" + hpds_port+ "/HP/Diagnostics_Server/Ver");

## Only version 8.x and 9.x are vulnerable
if(hpds_ver =~ "^(8|9)")
{
  ## Check HP Diagnostics Server 8.x through 8.07 and 9.x through 9.21
  if( version_in_range(version:hpds_ver, test_version:"8.00", test_version2:"8.07")||
      version_in_range(version:hpds_ver, test_version:"9.00", test_version2:"9.21"))
  {
    security_hole(hp_mgmt_port);
    exit(0);
  }
}
