###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icy_phoenix_mult_xss_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Icy Phoenix Multiple Cross-Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803952";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_bugtraq_id(62722);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vetor", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-08 15:21:12 +0530 (Tue, 08 Oct 2013)");
  script_name("Icy Phoenix Multiple Cross-Site Scripting Vulnerability");

  tag_summary =
"This host is installed with Icy Phoenix and is prone to cross-site scripting
vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it is able to
read the string or not.";

  tag_insight =
'An error exists in the application which fails to properly sanitize user-supplied
input to "subject" parameter before using it.';

  tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

  tag_affected =
"Icy Phoenix version 2.0, Lower versions may also be affected.";

  tag_solution =
"No solution available as of October 8, 2013.Information regarding this
issue will be updated once the solution details are available.
For updates refer to //http://www.icyphoenix.com";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50890");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79115");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123446");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/117197");
  script_summary("Check if Icy Phoenix is vulnerable to XSS");
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

## Iterate over possible paths
foreach dir (make_list("", "/icyphoenix", "/ip", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/index.php"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(res && (egrep(pattern:"Powered by.*Icy Phoenix.*phpBB", string:res)))
  {
    ## Construct the attack request
    url = dir + "/index.php?>'" + '"><script>alert(01234567891);</script>=';

    match = "<script>alert\(01234567891);<\/script>";
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:match))
    {
      security_warning(port);
      exit(0);
    }
  }
}
