###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_cybozu_products_detect.nasl 13 2013-10-27 12:16:33Z jan $
#
# Cybozu Products Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_summary = "This script finds the running Cybozu Products version and
  saves the result in KB.";

if(description)
{
  script_id(902533);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("Cybozu Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set the version of Cybozu Products in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

foreach dir (make_list("/scripts", cgi_dirs()))
{
  ## Cybozu Garoon
  foreach path (make_list("/cbgrn", "/garoon", "/grn"))
  {
    ## Send and Recieve the response
    req = http_get(item:string(dir, path, "/grn.exe"), port:port);
    res = http_keepalive_send_recv(port:port, data: req);

    ## Confirm the application
    if("Cybozu" >< res && "Garoon" >< res)
    {
      ## Try to get the version
      ver = eregmatch(pattern:"Version ([0-9.]+)", string: res);
      if(ver[1])
      {
        ## Set the KB value
        set_kb_item(name:"www/" + port + "/CybozuGaroon", value:ver[1] +
                         " under " + dir);
        security_note(data:"Cybozu Garoon version " + ver[1] +
                           " running at location "  + dir + path +
                           " was detected on the host", port:port);
      }
    }
  }

  ## Cybozu Office
  foreach path (make_list("/cbag", "/office"))
  {
    ## Send and Recieve the response
    req = http_get(item:string(dir, path, "/ag.exe"), port:port);
    res = http_keepalive_send_recv(port:port, data: req);

    ## Confirm the application
    if("Cybozu" >< res && "Office" >< res)
    {
      ## Try to get the version
      ver = eregmatch(pattern:"Office Version ([0-9.]+)", string: res);
      if(ver[1])
      {
        ## Set the KB value
        set_kb_item(name:"www/" + port + "/CybozuOffice", value:ver[1] +
                         " under " + dir);
        security_note(data:"Cybozu Office version " + ver[1] +
                           " running at location "  + dir + path +
                           " was detected on the host", port:port);
      }
    }
  }

  ## Cybozu Dezie
  foreach path (make_list("/cbdb", "/dezie"))
  {
    ## Send and Recieve the response
    req = http_get(item:string(dir, path, "/db.exe"), port:port);
    res = http_keepalive_send_recv(port:port, data: req);

    ## Confirm the application
    if("Cybozu" >< res && "Dezie" >< res)
    {
      ## Try to get the version
      ver = eregmatch(pattern:"Version ([0-9.]+)", string: res);
      if(ver[1])
      {
        ## Set the KB value
        set_kb_item(name:"www/" + port + "/CybozuDezie", value:ver[1] +
                         " under " + dir);
        security_note(data:"Cybozu Dezie version " + ver[1] +
                           " running at location "  + dir + path +
                           " was detected on the host", port:port);
      }
    }
  }

  ## Cybozu MailWise
  foreach path (make_list("/cbmw", "/mailwise"))
  {
    ## Send and Recieve the response
    req = http_get(item:string(dir, path, "/mw.exe"), port:port);
    res = http_keepalive_send_recv(port:port, data: req);

    ## Confirm the application
    if("Cybozu" >< res && "mailwise" >< res)
    {
      ## Try to get the version
      ver = eregmatch(pattern:"Version ([0-9.]+)", string: res);
      if(ver[1])
      {
        ## Set the KB value
        set_kb_item(name:"www/" + port + "/CybozuMailWise", value:ver[1] +
                         " under " + dir);
        security_note(data:"Cybozu MailWise version " + ver[1] +
                           " running at location "  + dir + path +
                           " was detected on the host", port:port);
      }
    }
  }
}
