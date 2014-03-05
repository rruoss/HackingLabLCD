###################################################################
# OpenVAS Network Vulnerability Test
#
# Sympa Detection
#
# LSS-NVT-2009-013
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
tag_summary = "The remote host is running Sympa, an open source (GNU GPL) mailing list management (MLM) software
suite written in Perl.";

if(description)
{
 script_id(102013);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 43 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name("Sympa Detection");

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);

 script_summary("Detects Sympa");

 script_category(ACT_GATHER_INFO);

 script_copyright("Copyright (C) 2009 LSS");
 script_family("Service detection");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80, 443);
 
 script_xref(name : "URL" , value : "http://www.sympa.org/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("openvas-https.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.102013";
SCRIPT_DESC = "Sympa Detection";


# Function that checks each dir for Sympa installation
# Optionally can use https

function CheckSympa(use_https) {
  dirs = make_list("/sympa", cgi_dirs());

  # Go through dirs
  foreach dir (dirs)
  {
    url = string(dir, "/");
    req = http_get(item:url, port:port);
    if(use_https==1)
      req = https_req_get(request: req, port:port);
    else
      req = http_send_recv(data: req, port:port);
      
    if(isnull(req)) return;

    # Check if it is Sympa
    pat='Powered by ([^>]*>)?Sympa ?v?([0-9.]+)';
    match=egrep(pattern:pat,string:req, icase:1);
    
    if(match || egrep(pattern:"<meta name=.generator. content=.Sympa",string:req,icase=1)) {
      
      # Instalation found, extract version
      item=eregmatch(pattern:pat,string:match, icase:1);
      ver=item[2];

      # If version couldn't be extracted, mark as unknown
      if(!ver) ver="unknown";

      tmp_version = string(ver, " under ", dir);
      set_kb_item(name:string("www/", port, "/sympa"),value:tmp_version);
   
      ## build cpe and store it as host_detail
      cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:sympa:sympa:");
      if(!isnull(cpe))
         register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

      if(report_verbosity) {
        if(dir=="") dir="/";
        info+=" Version: " +ver + " under "+dir+'\n'+'\n';
      }
      n++;
      if(!thorough_tests) break;
    }
  }
}

n=0;
info="";

# Check for installations on https
port = get_kb_item("Services/www");
if(!port) port = 443;
if (get_port_state(port))
  CheckSympa(use_https: 1);

# Check for installations on http
if(!n || thorough_tests) {
  port = get_http_port(default:80);
  if (get_port_state(port))
    CheckSympa(use_https: 0);
}

if(!n) exit(0);

if(report_verbosity) {
  info="The following version(s) of Sympa were detected: "+'\n'+'\n'+info;
  security_note(port:port, data:info);
} else
  security_note(port:port);
