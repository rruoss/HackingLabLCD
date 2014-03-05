###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clicknet_cms_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Clicknet CMS 'index.php' Directory Traversal Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful attacks will allow attackers to read arbitrary files via a
  '..' (dot dot) sequences.

  Impact level: Application";

tag_affected = "Clicknet CMS version 2.1 and prior.";
tag_insight = "The flaw is due to error in 'side' parameter in index.php which is not
  adequately sanitised that may lead to directory traversal attacks.";
tag_solution = "No solution or patch is available as of 08th July, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://cms.clicknet.dk/";
tag_summary = "This host has Clicknet CMS installed and is prone to Directory
  Traversal vulnerability.";

if(description)
{
  script_id(800903);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-09 10:58:23 +0200 (Thu, 09 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2325");
  script_name("Clicknet CMS 'index.php' Directory Traversal Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35607");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9037");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1736");

  script_description(desc);
  script_summary("Check for Attack and version of Clicknet CMS");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_clicknet_cms_detect.nasl");
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

clickPort = get_http_port(default:80);
if(!clickPort){
  exit(0);
}

clickVer = get_kb_item("www/" + clickPort +"/Clicknet-CMS");
clickVer = eregmatch(pattern:"^(.+) under (/.*)$", string:clickVer);

if(clickVer[2] != NULL && !safe_checks())
{
  sndReq = http_get(item:string(clickVer[2] + "/index.php?side=../index"),
                    port:clickPort);
  rcvRes = http_send_recv(port:clickPort, data:sndReq);

  if("DOCUMENT_ROOT" >< rcvRes && "explode" >< rcvRes)
  {
    security_warning(clickPort);
    exit(0);
  }
}

if(clickVer[1] == NULL){
  exit(0);
}

if(version_is_less_equal(version:clickVer[1], test_version:"2.1")){
  security_warning(clickPort);
}
