###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ocs_inventory_ng_mult_xss_sql_vul.nasl 14 2013-10-27 12:33:37Z jan $
#
# OCS Inventory NG Multiple Vulnerabilities
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
tag_impact = "Successful exploitation could allow attackers to inject arbitrary web script
  or HTML and conduct Cross-Site Scripting attacks.
  Impact Level: Application";
tag_affected = "OCS Inventory NG 1.02.1 and prior.";
tag_insight = "Multiple flaws are due to,
  - improper validation of user-supplied input via 1)the query string,
    (2)the BASE parameter, or (3)the ega_1 parameter in ocsreports/index.php.
   that allow remote attackers to inject arbitrary web script or HTML.
  - improper validation of user-supplied input via (1)c, (2)val_1, or
    (3)onglet_bis parameter in ocsreports/index.php that allow remote attackers
    to execute arbitrary SQL commands.";
tag_solution = "Upgrade to the latest version of OCS Inventory NG 1.02.3 or later,
  For updates refer to http://sourceforge.net/projects/ocsinventory";
tag_summary = "This host is running OCS Inventory NG and is prone to multiple
  cross-site scripting and SQL injection vulnerabilities.";

if(description)
{
  script_id(801204);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-05 15:59:12 +0200 (Wed, 05 May 2010)");
  script_bugtraq_id(38131);
  script_cve_id("CVE-2010-1594","CVE-2010-1595");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("OCS Inventory NG Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38311");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1001-exploits/ocsinventoryng-sqlxss.txt");

  script_description(desc);
  script_summary("Check for the version of OCS Inventory NG");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/", "/ocsreports", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(">OCS Inventory<" >< res)
  {
    ## Get OCS Inventory NG Version
    ver = eregmatch(pattern:"Ver.? ?([0-9.]+).?", string:res);

    if(ver[1])
    {
      ## Check for version before 1.02.1
      if(version_in_range(version:ver[1], test_version:"1.02",
                                          test_version2:"1.02.1"))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
