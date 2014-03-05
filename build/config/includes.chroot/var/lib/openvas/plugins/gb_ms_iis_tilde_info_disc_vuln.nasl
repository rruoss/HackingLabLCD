###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_iis_tilde_info_disc_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft IIS Tilde Character Information Disclosure Vulnerability
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Microsoft Internet Information Services versions 7.5 and prior";
tag_insight = "Microsoft IIS fails to validate a specially crafted GET request containing a
  '~' tilde character, which allows to disclose all short-names of folders and
  files having 4 letters extensions.";
tag_solution = "No solution or patch is available as of 18th July, 2012. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.iis.net/";
tag_summary = "This host is running Microsoft IIS Webserver and is prone to
  information disclosure vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802887";
CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54251);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-18 10:29:25 +0530 (Wed, 18 Jul 2012)");
  script_name("Microsoft IIS Tilde Character Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/83771");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/19525");
  script_xref(name : "URL" , value : "http://code.google.com/p/iis-shortname-scanner-poc");
  script_xref(name : "URL" , value : "http://soroush.secproject.com/downloadable/iis_tilde_shortname_disclosure.txt");
  script_xref(name : "URL" , value : "http://soroush.secproject.com/downloadable/microsoft_iis_tilde_character_vulnerability_feature.pdf");

  script_description(desc);
  script_summary("Determine if it is possible to get file/folder names");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("IIS/installed");
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

## Variables Initialization
iisVer = "";
url1 = "";
url2 = "";
url3 = "";
count = 0;
port = 0;
iisreq1 = "";
iisres1 = "";
iisreq2 = "";
iisres2 = "";
iisreq3 = "";
iisres3 = "";
valid_letter = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check port state
if(!get_port_state(port)){
  exit(0);
}

## Get installed IIS version
iisVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);
if(!iisVer){
  exit(0);
}

## List of all possible letters a folder/file name may have
possilbe_letters = make_list('0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                     'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                     'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                     'y', 'z');

## List of all possible files
files = make_list("a.aspx","a.shtml","a.asp","a.asmx","a.ashx","a.config","a.php","a.jpg","a.xxx","");

foreach file (files)
{
  url1 = "/%2F*~1*%2F" + file + "?aspxerrorpath=/";

  iisreq1 = http_get(item:url1, port:port);
  iisres1 = http_keepalive_send_recv(port:port, data:iisreq1, bodyonly:FALSE);

  ## Check if the file with extension is valid
  ## Check status Code 400 or error code 0x80070002 (IIS 7.x)
  if(!iisres1 || (iisVer !~ "^7" && iisres1 !~ "HTTP/1.. 404")||
     (iisVer =~ "^7" && iisres1 !~ "Error Code</th><td>0x00000000")){
   continue;
  }

  url2 = "/%2F1234567890*1~*%2F" +file + "?aspxerrorpath=/";

  ## Send the second request 
  iisreq2 = http_get(item:url2, port:port);
  iisres2 = http_keepalive_send_recv(port:port, data:iisreq2, bodyonly:FALSE);

  ## Check the status code for reliability
  ## Check if Status code 400 or error code 0x80070002
  if(iisres2 && (iisVer !~ "^7" && iisres2 =~ "HTTP/1.. 400")||
     (iisVer =~ "^7" && iisres2 =~ "Error Code</th><td>0x80070002"))
  {

    ## Now iterate over all possible letters to find the file or folders names
    while (count < 4)
    {
      foreach letter (possilbe_letters)
      {
        ## Construt a valid request will all possible letters to find a valid name
        url3 = "/%2F" + valid_letter + letter + "*~1*%2F" +file+ "?aspxerrorpath=/";

        iisreq3 = http_get(item:url3, port:port);
        iisres3 = http_keepalive_send_recv(port:port, data:iisreq3, bodyonly:FALSE);

        ## Check the statuscode for each letter
        ## If its 404 then its a valid letter and there is file/folder starting with that letter
        if(!iisres3 || (iisVer !~ "^7" && iisres3 !~ "HTTP/1.. 404")||
            (iisVer =~ "^7" && iisres3 !~ "Error Code</th><td>0x00000000")){
          continue;
        }

        valid_letter += letter;
      }
      count++;

    }
    if(strlen(valid_letter) > 0)
    {
      msg = "File/Folder name found on server starting with :" + valid_letter ;
      log_message(port: port, data:msg);
      security_warning(port);
      exit(0);
    }
  }
}
