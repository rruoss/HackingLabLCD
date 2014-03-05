###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sphider_query_param_xss_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Sphider query Parameter Cross-Site Scripting Vulnerability
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
tag_impact = "Successful attack could lead to execution of arbitrary HTML or scripting code
  in the security context of an affected web page, which allows an attacker to
  steal cookie-based authentication credentials or access and modify data.";
tag_affected = "Sphider Version 1.3.4 and prior on all running platform.";
tag_insight = "The flaw is due to input passed into the query parameter in search.php
  when suggestion feature is enabled is not properly sanitized before being
  returned to a user.";
tag_solution = "No solution or patch is available as of 28th November, 2008. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.sphider.eu/";
tag_summary = "This host is running Sphider and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_id(800308);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5211");
  script_bugtraq_id(29074);
  script_name("Sphider query Parameter Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/42240");
  script_xref(name : "URL" , value : "http://users.own-hero.net/~decoder/advisories/sphider134-xss.txt");

  script_description(desc);
  script_summary("Check for the Version of Sphider");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_reg_enum.nasl");
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

foreach path (make_list("/sphider", cgi_dirs()))
{
  sndReq = http_get(item:string(path, "/changelog"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if(egrep(pattern:"Sphider .* search engine in PHP", string:rcvRes))
  {
    sphiderVer = eregmatch(pattern:"Sphider ([0-9.]+)", string:rcvRes);
    if(sphiderVer[1] != NULL)
    {
      # Grep for Sphider Version <= 1.3.4
      if(version_is_less_equal(version:sphiderVer[1], test_version:"1.3.4")){
        security_warning(port);
        exit(0);
      }
    }
  }
}
