###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oscss_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# osCSS Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_summary = "The script detects the version of osCSS on remote host
  and sets the KB.";


if(description)
{
  script_id(901135);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 44 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("osCSS Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Check for osCSS version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Service detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get http port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

foreach dir (make_list("/catalog", "/osCSS", "/", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir, "/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm the application
  if(">osCSS" >< rcvRes)
  {
    ## Get osCSS Version
    ver = eregmatch(pattern:'(<b>osCSS |<strong>)([0-9.]+)(.?([a-zA-Z0-9]+))?',
                             string:rcvRes);
    if(ver[2] != NULL)
    {
      if(ver[4] != NULL) {
        ocver = ver[2] + "." + ver[4];
      }
      else {
        ocver = ver[2];
      }
    }

    if(ocver)
    {
      ## Set the KB value
      set_kb_item(name:"www/" + port + "/osCSS", value:ocver + " under " + dir);
      security_note(data:"osCSS Version " + ocver + " running at location "
                          + dir +  " was detected on the host", port:port);
    }
  }
}
