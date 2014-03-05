###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_imagemanager_lfi_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Xoops 'imagemanager.php' Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to perform file inclusion
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Xoops versin 2.5.0 and prior.";
tag_insight = "The flaw is due to input validation error in 'target' parameter to
  'imagemanager.php', which allows attackers to read arbitrary files via a
  ../(dot dot) sequences.";
tag_solution = "No solution or patch is available as of th 06th May, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://sourceforge.net/projects/xoops/";
tag_summary = "This host is running with Xoops and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(801932);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-16 15:25:30 +0200 (Mon, 16 May 2011)");
  script_bugtraq_id(47418);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Xoops 'imagemanager.php' Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://dl.packetstormsecurity.net/1104-exploits/xoops250-lfi.txt");
  script_xref(name : "URL" , value : "http://www.allinfosec.com/2011/04/18/webapps-0day-xoops-2-5-0-imagemanager-php-lfi-vulnerability-2/");

  script_description(desc);
  script_summary("Check for local file inclusion vulnerability in OrangeHRM");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_dependencies("secpod_xoops_detect.nasl");
  script_family("Web application abuses");
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

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get XOOPS version from KB
xpVer = get_kb_item("www/"+ port + "/XOOPS");
if(!xpVer){
  exit(0);
}

xpVer = eregmatch(pattern:"([0-9.]+)", string:xpVer);
if(xpVer[1] != NULL)
{
  ## Check for the XOOPS version less or equal 2.5.0
  if(version_is_less_equal(version:xpVer[1], test_version:"2.5.0")){
    security_hole(port);
  }
}
