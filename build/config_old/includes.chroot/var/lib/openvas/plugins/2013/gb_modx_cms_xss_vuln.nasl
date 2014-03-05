###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_cms_xss_vuln.nasl 33 2013-10-31 15:16:09Z veerendragg $
#
# MODx CMS Cross Site Scripting Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804124";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 33 $");
  script_bugtraq_id(63274);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-31 16:16:09 +0100 (Do, 31. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-29 11:49:17 +0530 (Tue, 29 Oct 2013)");
  script_name("MODx CMS Cross Site Scripting Vulnerability");

  tag_summary =
"This host is running MODx CMS and is prone to cross site scripting
vulnerability";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the cookie or not.";

  tag_insight =
"Flaw exists due to improper sanitization of url, when accessing 'findcore.php'
and 'xpdo.class.php' scripts.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary HTML
or script code, steal cookie-based authentication credentials and launch
other attacks.

Impact Level: Application";

  tag_affected =
"MODx version 2.2.10, Other versions may also be affected.";

  tag_solution =
"No solution available as of October 29, 2013. Information regarding this
issue will be updated once the solution details are available.
For updates refer to http://modx.com";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/98834");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/88208");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Oct/108");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/modx-2210-cross-site-scripting");
  script_summary("Check if MODx CMS is vulnerable to cross site scripting");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list("", "/modx", "/cms", cgi_dirs()))
{
  req = http_get(item:string(dir, "/setup/templates/findcore.php"),  port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  ## confirm the Application
  if(res &&  ">MODX Revolution<" >< res)
  {
    ## Construct Attack Request
    url = dir + "/setup/templates/findcore.php/%22%3E%3Cscript%3Ealert(document.cookie);%3C/script%3E" ;

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:http_port, url:url, check_header:TRUE,
                       pattern:"<script>alert\(document.cookie\);</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
