###############################################################################
# OpenVAS Vulnerability Test
# $Id: photopost_detect.nasl 43 2013-11-04 19:51:40Z jan $
#
# Photopost Detection
#
# Authors:
# LSS Security Team <http://security.lss.hr>
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 LSS <http://www.lss.hr> / Greenbone Networks GmbH 
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "This host is running Photopost, a photo sharing gallery software.";

# need desc here to modify it later in script.
desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_id(100285);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-10-02 19:48:14 +0200 (Fri, 02 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Photopost Detection");

 script_description(desc);
 script_summary("Checks for the presence of Photopost");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 LSS / Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.photopost.com/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100285";
SCRIPT_DESC = "Photopost Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/photopost","/photos","/gallery","/photo",cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php
  url = string(dir, "/index.php");
  req = http_send_recv(data:http_get(item:url, port:port), port:port);
  if(isnull(req)) exit(0);

  # Check if it is PhotoPost
  match=egrep(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost',string:req, icase:1);
  if(match) {
    # If PhotoPost detected, try different grep to extract version
    match=egrep(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)',string:req, icase:1);
    if(match)
      item=eregmatch(pattern:'Powered by[^>]*>(<font[^>]*>)?PhotoPost.*PHP ([0-9.a-z]+)',string:match, icase:1);
    ver=item[2];

    # If version couldn't be extracted, mark as unknown
    if(!ver) ver="unknown";

    # PhotoPost installation found
    tmp_version = string(ver, " under ", dir);
    set_kb_item(name:string("www/", port, "/photopost"),value:tmp_version);
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:photopost:photopost_php_pro:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    if(report_verbosity) {
      if(dir=="") dir="/";
      info+=ver + " under " + dir + '\n';
    }
    n++;
    if(!thorough_tests) break;
  }
}

if(!n) exit(0);

if(report_verbosity) {
  info='\n\n' + "The following version(s) of PhotoPost were detected: " + '\n\n'+info;
  desc+=info;
  security_note(port:port, data:desc);
  exit(0);
}

exit(0);

