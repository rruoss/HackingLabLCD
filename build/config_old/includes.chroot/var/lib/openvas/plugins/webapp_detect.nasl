###################################################################
# OpenVAS Network Vulnerability Test
#
# WebAPP Detection
#
# LSS-NVT-2009-009
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "The remote host is running WebAPP, an open source web portal written
in Perl.";

desc = "
 Summary:
 " + tag_summary;


if(description)
{
 script_id(102009);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-09-18 16:06:42 +0200 (Fri, 18 Sep 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("WebAPP Detection");

 script_description(desc);
 summary = "Detects WebAPP";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 script_copyright("Copyright (C) 2009 LSS");
 script_family("Service detection");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);

 script_xref(name : "URL" , value : "http://www.web-app.org/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.102009";
SCRIPT_DESC = "WebAPP Detection";

port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);

n=0;

# Go through dirs
foreach dir (cgi_dirs())
{
  # Grab index
  found=0;
  url = string(dir, "/");
  req = http_send_recv(data:http_get(item:url, port:port), port:port);
  if(isnull(req)) exit(0);

  pat='<meta name=.Generator. content=.WebAPP[^0-9]*([^>"]*)';
  match=egrep(pattern:pat,string:req,icase=1);

  # If match is found, try to extract the version
  if(match) {
    item=eregmatch(pattern:pat,string:match, icase:1);
    ver=item[1];

    found=1;
  }

  # If version is empty, try different approach
  if(!ver) {
    pat='This site was made with[^>]*>WebAPP([^>]*>)*[^>]*>v([0-9.]*)';
    item=eregmatch(pattern:pat,string:req, icase:1);
    if(item) {
      ver=item[2];
      found=1;
    }
  }

  if(!ver && found) ver="unknown";
  if(found) {
    # WebApp installation found
    if(dir=="") dir="/";

    tmp_version = string(ver, " under ", dir);
    set_kb_item(name:string("www/", port, "/webapp"),value:tmp_version);
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:web_app.net:webapp:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    if(report_verbosity) {
      info+=ver + " under " + dir + '\n';
    }
    n++;
    if(!thorough_tests) break;
  }
}

if(!n) exit(0);



if(report_verbosity) {
  info="The following version(s) of WebAPP were detected: "+'\n\n'+info;
  desc+=info;
  security_note(port:port, data:desc);
}

