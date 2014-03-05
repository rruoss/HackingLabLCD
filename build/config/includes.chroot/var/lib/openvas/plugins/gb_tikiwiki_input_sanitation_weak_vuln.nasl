###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tikiwiki_input_sanitation_weak_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# TikiWiki CMS/Groupware Input Sanitation Weakness Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow arbitrary code execution in the context
  of an affected site.
  Impact Level: Application";
tag_affected = "TikiWiki CMS/Groupware version prior to 2.2 on all running platform";
tag_insight = "The vulnerability is due to input validation error in tiki-error.php
  which fails to sanitise before being returned to the user.";
tag_solution = "Upgrade to version 2.2 or latest
  http://info.tikiwiki.org/tiki-index.php?page=Get+Tiki&bl";
tag_summary = "The host is installed with TikiWiki and is prone to input sanitation
  weakness vulnerability.";

if(description)
{
  script_id(800315);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5318", "CVE-2008-5319");
  script_name("TikiWiki CMS/Groupware Input Sanitation Weakness Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/50058");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32341");
  script_xref(name : "URL" , value : "http://info.tikiwiki.org/tiki-read_article.php?articleId=41");

  script_description(desc);
  script_summary("Check for the Version of TikiWiki CMS/Groupware");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach path (make_list("/tikiwiki", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/README"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("Tikiwiki" >< rcvRes)
  {
    tikiVer = eregmatch(pattern:"version ([0-9.]+)", string:rcvRes);
    if(tikiVer[1] != NULL)
    {
      if(version_is_less(version:tikiVer[1], test_version:"2.2")){
        security_warning(port);
      }
    }
    exit(0);
  }
}
