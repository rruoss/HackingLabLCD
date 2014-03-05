##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openmairie_openpresse_lfi_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# openMairie openPresse 'dsn[phptype]' Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information or execute arbitrary code on the vulnerable Web server.
  Impact Level: Application.";
tag_affected = "OpenMairie OpenPresse version 1.01 and prior";

tag_insight = "Input passed to the parameter 'dsn[phptype]' in 'scr/soustab.php' is not
  properly verified before being used to include files.";
tag_solution = "No solution or patch is available as of 20th May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://adullact.net/frs/?group_id=304";
tag_summary = "This host is running openMairie openPresse and is prone to
  local file inclusion vulnerability.";

if(description)
{
  script_id(800783);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1935");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("openMairie openPresse 'dsn[phptype]' Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39605");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58090");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/12364");

  script_description(desc);
  script_summary("Check for the exploit string on OpenMairie openPresse");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openmairie_prdts_detect.nasl");
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

openPort = get_http_port(default:80);
if(!get_port_state(openPort)){
  exit(0);
}

## Get openPresse version from KB
openVer = get_kb_item("www/"+ openPort + "/OpenMairie/Open_Presse");
if(!openVer){
 exit(0);
}

openVer = eregmatch(pattern:"^(.+) under (/.*)$", string:openVer);

if(openVer[2] != NULL)
{
  ## Check for the Exploit
  sndReq = http_get(item:string(openVer[2], "/scr/soustab.php?dsn[phptype]=" +
                    "../../../../../../../../OpenVas-rfi.txt"),port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  ## Check the attack response
  if("/OpenVas-rfi.txt/" >< rcvRes && "failed to open stream" >< rcvRes){
    security_hole(openPort);
  }
}