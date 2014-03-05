##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_piwigo_csrf_n_path_trav_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Piwigo Cross Site Request Forgery and Path Traversal Vulnerabilities
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
tag_impact = "Successful exploitation will allow remote attackers to create arbitrary PHP
  file or to retrieve and delete arbitrary files in the context of the
  affected application.
  Impact Level: Application";
tag_affected = "Piwigo version 2.4.6 and prior";


tag_insight = "- Flaw in the LocalFiles Editor plugin, it does not require multiple steps
    or explicit confirmation for sensitive transactions.
  - Input passed via 'dl' parameter to install.php is not properly sanitized
    before being used.";
tag_solution = "Upgrade to Piwigo version 2.4.7
  For updates refer to http://piwigo.org/releases/2.4.7";
tag_summary = "This host is installed with Piwigo and is prone to cross site
  request forgery and path traversal vulnerabilities.";

if(description)
{
  script_id(803340);
  script_version("$Revision: 11 $");
  script_bugtraq_id(58016,58080);
  script_cve_id("CVE-2013-1468","CVE-2013-1469");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-21 13:40:26 +0530 (Thu, 21 Mar 2013)");
  script_name("Piwigo Cross Site Request Forgery and Path Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://osvdb.org/90504");
  script_xref(name : "URL" , value : "http://osvdb.org/90357");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Feb/152");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24561");
  script_xref(name : "URL" , value : "http://www.htbridge.com/advisory/HTB23144");

  script_description(desc);
  script_summary("Check if Piwigo is vulnerable to path traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
rcvRes = "";
SendReq = "";

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

foreach dir (make_list("/piwigo", "/gallery", "/photos", "", cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm application
  if("<title>Piwigo, Welcome" >< rcvRes)
  {
    ## Construct Attack Request
    url = dir + '/install.php?dl=/../../local/config/ovtestlmn678.php';

    ## Check the response to confirm vulnerability
    ## Actual file, '/database.inc.php' gets deleted and information cannot be
    ## fetched. Hence we are using dummy file 'openvastest.php' to check the
    ## response. The patched version of application will generate a different
    ## response.
    if(http_vuln_check(port: port, url: url, check_header: TRUE,
       pattern: "Piwigo is already installed"))
    {
      security_hole(port);
      exit(0);
    }
  }
}
