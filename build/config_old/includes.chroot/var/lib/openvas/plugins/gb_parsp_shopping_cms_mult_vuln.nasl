###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_parsp_shopping_cms_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Parsp Shopping CMS Multiple Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site and gain th sensitive information related to PHP.
  Impact Level: Application";
tag_affected = "Parsp Shopping CMS version V5 and prior.";
tag_insight = "The flaws are due to an,
  - Input passed to the 'advanced_search_in_category' parameter in 'index.php'
    is not properly sanitised before being returned to the user.
  - Error in 'phpinfo.php' script, this can be exploited to gain knowledge
    of sensitive information by requesting the file directly.";
tag_solution = "No solution or patch is available as of 03rd, February 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.parsp.com/";
tag_summary = "This host is running Parsp Shopping CMS and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802575);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-01 15:28:20 +0530 (Wed, 01 Jan 2012)");
  script_name("Parsp Shopping CMS Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploits/17418");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18409/");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2012010198");
  script_xref(name : "URL" , value : "http://www.exploitsdownload.com/search/Arab");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108953/parspshoppingcms-xssdisclose.txt");

  script_description(desc);
  script_summary("Check if Parsp Shopping CMS is prone to multiple vulnerabilites");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get the host name
host = get_host_name();
if(!host){
  exit(0);
}

foreach dir (make_list("/", "/parsp", cgi_dirs()))
{
  sndReq = string("GET ", dir, "/index.php HTTP/1.1", "\r\n",
                  "Host: ", host, "\r\n\r\n");
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(egrep(pattern:'>powered by .*>www.parsp.com<', string:rcvRes))
  {
    ## Attack to obtain information about php
    sndReq = string("GET ", dir, "/phpinfo.php HTTP/1.1", "\r\n",
                    "Host: ", host, "\r\n\r\n");
    rcvRes = http_send_recv(port:port, data:sndReq);

    ## Confirm exploit worked properly or not
    if("<title>phpinfo" >< rcvRes && ">PHP Core<" >< rcvRes)
    {
      security_warning(port:port);
      exit(0);
    }
  }
}
