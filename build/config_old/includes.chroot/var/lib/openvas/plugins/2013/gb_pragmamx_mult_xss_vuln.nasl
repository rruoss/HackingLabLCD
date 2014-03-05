###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pragmamx_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# PragmaMX Multiple Cross-Site Scripting Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  or web script in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_affected = "PragmaMX version 1.12.1 and prior";
tag_insight = "Multiple flaws due to input passed via 'name' parameter to modules.php and
  'img_url' parameter to img_popup.php is not properly sanitised before being
  returned to the user.";
tag_solution = "Upgrade to PragmaMx 1.12.2 or later,
  For updates refer to http://www.pragmamx.org";
tag_summary = "The host is installed with PragmaMX and is prone to multiple cross
  site scripting vulnerabilities.";

if(description)
{
  script_id(803345);
  script_version("$Revision: 11 $");
  script_bugtraq_id(53669);
  script_cve_id("CVE-2012-2452");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-25 16:37:00 +0530 (Mon, 25 Mar 2013)");
  script_name("PragmaMX Multiple Cross-Site Scripting Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/82059");
  script_xref(name : "URL" , value : "http://osvdb.org/82058");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/May/126");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23090");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/113035");
  script_xref(name : "URL" , value : "http://www.pragmamx.org/Content-pragmaMx-changelog-item-75.html");

  script_description(desc);
  script_summary("Check if PragmaMX is vulnerable to XSS vulnerability");
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

foreach dir (make_list("", "/pragmamx", "/cms", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"),  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>pragmaMx' >< res)
  {
    ## Construct Attack Request
    url = dir +'/includes/wysiwyg/spaw/editor/plugins/imgpopup/img_popup.php?'+
               'img_url="><script>alert(document.cookie)</script>';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "<script>alert\(document.cookie\)</script>"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
