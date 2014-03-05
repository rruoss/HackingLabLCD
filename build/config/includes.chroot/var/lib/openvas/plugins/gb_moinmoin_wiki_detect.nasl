###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_detect.nasl 44 2013-11-04 19:58:48Z jan $
#
# MoinMoin Wiki Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_summary = "Detection of MoinMoin Wiki.

This script detects the installed version of MoinMoin Wiki
and sets the result in KB.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800170";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 44 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:58:48 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_name("MoinMoin Wiki Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Set version of MoinMoin Wiki in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Variables Initialization
cpe = "";
path = "";
port = "";
sndReq = "";
rcvRes = "";
moinWikiVer = "";
moinWikiPort = "";


## Get MoinMoin Wiki port
moinWikiPort = get_http_port(default: 8080);
if(!moinWikiPort){
  moinWikiPort = 8080;
}

## Check Port status
if(!get_port_state(moinWikiPort)){
  exit(0);
}

## set the kb and CPE
function _SetCpe(moinWikiVer, moinWikiPort, path)
{
  ## set the kb
  set_kb_item(name: string("www/", moinWikiPort, "/moinmoinWiki"),
              value: string(moinWikiVer," under ",path));
  set_kb_item(name: "moinmoinWiki/installed", value: TRUE);

  ## build cpe
  cpe = build_cpe(value: moinWikiVer, exp: "^([0-9.]+)", base: "cpe:/a:moinmo:moinmoin:");
  if(isnull(cpe))
    cpe = 'cpe:/a:moinmo:moinmoin';

  ## register the product
  register_product(cpe: cpe, location: path, nvt: SCRIPT_OID, port: moinWikiPort);
  log_message(data: build_detection_report(app: "moinmoinWiki",
                                          version: moinWikiVer,
                                          install: path,
                                          cpe: cpe,
                                          concluded: moinWikiVer,
                                          port: moinWikiPort));
  exit(0);
}

## Get the banner to check version
banner = get_http_banner(port: moinWikiPort);
if(banner)
{
  moinWikiVer = eregmatch(pattern: "MoinMoin ([0-9.a-z]+)", string: banner);
  path = "/";
}

## If Unable to get version from banner get it from page
if(!moinWikiVer)
{
  ## Iterate over the possible paths
  foreach path (make_list("", "/Moin", "/moin", "/wiki", cgi_dirs()))
  {
    ## Send the request and Recieve the response
    sndReq = http_get(item: path + "/SystemInfo", port: moinWikiPort);
    rcvRes = http_send_recv(port: moinWikiPort, data: sndReq);

    ## Check for MoinMoin and SystemInfo in the response
    if("SystemInfo" >< rcvRes && ">MoinMoin " >< rcvRes )
    {
      ## Get MoinMoin Wiki Version
      moinWikiVer = eregmatch(pattern: "Release ([0-9.a-z]+) \[Revision release\]",
                              string: rcvRes);
    }
  }
}

if(moinWikiVer && moinWikiVer[1]){
  _SetCpe(moinWikiVer: moinWikiVer[1], moinWikiPort: moinWikiPort, path: path);
}
