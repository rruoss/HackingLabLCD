##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpgenealogie_rfi_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# PHPGenealogie 'CoupleDB.php' Remote File Inclusion Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code on
  the vulnerable Web server.

  Impact level: Application/System";

tag_affected = "PHPGenealogie version 2.0";
tag_insight = "The flaw is due to error in 'DataDirectory' parameter in 'CoupleDB.php' which
  is not properly verified before being used to include files.";
tag_solution = "No solution or patch is available as of 07th October, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/phpgenealogie/files/";
tag_summary = "This host is running PHPGenealogie and is prone to Remote File
  Inclusion vulnerability.";

if(description)
{
  script_id(801008);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-3541");
  script_name("PHPGenealogie 'CoupleDB.php' Remote File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9155");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51728");

  script_description(desc);
  script_summary("Check for the version and attack of PHPGenealogie");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_phpgenealogie_detect.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

phpgenPort = get_http_port(default:80);
if(!phpgenPort){
  exit(0);
}

phpgenVer = get_kb_item("www/" + phpgenPort + "/PHPGenealogie");
phpgenVer = eregmatch(pattern:"^(.+) under (/.*)$", string:phpgenVer);

if((phpgenVer[2] != NULL) && (!safe_checks()))
{
  sndReq = http_get(item:string(phpgenVer[2], "/CoupleDB.php?Parametre=0&" +
                         "DataDirectory=xyz/OpenVAS-RemoteFileInclusion.txt"),
                    port:phpgenPort);
  rcvRes = http_send_recv(port:phpgenPort, data:sndReq);
  if("xyz/OpenVAS-RemoteFileInclusion.txt" >< rcvRes)
  {
    security_hole(phpgenPort);
    exit(0);
  }
}
else
{
  if(phpgenVer[1] != NULL)
  {
    if(version_is_equal(version:phpgenVer[1], test_version:"2.0")){
      security_hole(phpgenPort);
    }
  }
}
