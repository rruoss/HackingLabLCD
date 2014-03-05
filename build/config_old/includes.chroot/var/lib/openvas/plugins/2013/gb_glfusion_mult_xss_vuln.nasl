###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_glfusion_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# glFusion Multiple Cross-Site Scripting Vulnerabilities
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation allow remote attackers to execute arbitrary code
  in the browser to steal cookie-based authentication credentials and launch
  other attacks.
  Impact Level: Application";

tag_affected = "glFusion version 1.2.2 and prior";
tag_insight = "The flaws are due
  - Insufficient filtration of user data in URL after
    '/admin/plugins/mediagallery/xppubwiz.php'
  - Insufficient filtration of user data passed to '/profiles.php',
    '/calendar/index.php' and '/links/index.php' via following parameters,
    'subject', 'title', 'url','address1', 'address2', 'calendar_type','city',
    'state', 'title', 'url', 'zipcode'.";
tag_solution = "Upgrade to the latest version of glFusion 1.2.2.pl4 or later,
  For updates refer to http://www.glfusion.org/filemgmt/index.php";
tag_summary = "This host is running glFusion and is prone to multiple cross-site
  scripting vulnerabilities.";

if(description)
{
  script_id(803316);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1466");
  script_bugtraq_id(58058);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-01 11:22:26 +0530 (Fri, 01 Mar 2013)");
  script_name("glFusion Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24536");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23142");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/120423/glFusion-1.2.2-Cross-Site-Scripting.html");

  script_description(desc);
  script_summary("Check if glFusion is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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

foreach dir (make_list("", "/glfusion", "/fusion", "/cms", cgi_dirs()))
{
  ## Send and Recieve the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>glFusion' >< res)
  {
    ## Construct Attack Request
    url = dir + '/admin/plugins/mediagallery/xppubwiz.php/'+
                '><script>alert(document.cookie)</script>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>",
       extra_check: make_list("User Name","Password")))
    {
      security_warning(port);
      exit(0);
    }
  }
}
