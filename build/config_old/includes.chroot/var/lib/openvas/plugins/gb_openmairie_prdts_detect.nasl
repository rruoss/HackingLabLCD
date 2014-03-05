###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openmairie_prdts_detect.nasl 14 2013-10-27 12:33:37Z jan $
#
# OpenMairie Products Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-20
#   - To detect some more products
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-05-21
#  - Updated to detect Opencatalogue product
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
tag_summary = "This script finds the installed OpenMairie products version and
  saves the result in KB.";

if(description)
{
  script_id(800779);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("OpenMairie Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;

  script_description(desc);
  script_summary("Set the version of OpenMairie Products in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Service detection");
  script_require_ports("Services/www", 80);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800779";
SCRIPT_DESC = "OpenMairie Products Version Detection";

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
## Get HTTP port
openPort = get_http_port(default:80);
if(!openPort){
  openPort = 80;
}

if(!get_port_state(openPort)){
  exit(0);
}

list = make_list("/openmairie_annuaire", "/Openmairie_Annuaire",
                 "/openmairie_courrier","/Openmairie_Courrier",
                 "/openmairie_planning", "/Openmairie_Planning",
                 "/openmairie_presse", "/Openmairie_Presse",
                 "/openmairie_cominterne", "/Openmairie_Cominterne",
                 "/openmairie_foncier", "/Openmairie_Foncier",
                 "/openmairie_registreCIL", "/Openmairie_RegistreCIL",
                 "/openmairie_cimetiere", "/Openmairie_Cimetiere", "/", cgi_dirs());

foreach dir(list)
{
  sndReq = http_get(item:string(dir , "/index.php"), port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  ## Checking for openAnnuaire product
  if(">Open Annuaire&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Annuaire
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Annuaire",
                  value:tmp_version);
      security_note(data:"Open Annuaire version " + openVer[1] +
                   " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openannuaire:");

    }
  }

  ## Checking for openCourrier product
  if(">Open Courrier&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)([a-z]*)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Courrier
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Courrier",
                  value:tmp_version);
      security_note(data:"Open Courrier version " + openVer[1] +
                   " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:opencourrier:");

     # exit(0);
    }
  }

  ## Checking for openCourrier product
  if("courrier" >< rcvRes)
  {
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Courrier
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Courrier",
                value:tmp_version);
      security_note(data:"Open Courrier version " + openVer[1] +
                 " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:opencourrier:");

     }
   }

   ## Checking for openPresse product
   if("presse" >< rcvRes)
   {
     openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
     if(openVer[1] != NULL)
     {
       ## Set the version of Open Presse
       tmp_version = openVer[1] + " under " + dir;
       set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Presse",
                value:tmp_version);
        security_note(data:"Open Presse version " + openVer[1] +
                 " running at location " + dir + " was detected on the host");

       ## build cpe and store it as host_detail
       register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openpresse:");

      }
   }

  ## Checking for openPlanning product
  if(">Open Planning&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Planning
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Planning",
                  value:tmp_version);
      security_note(data:"Open Planning version " + openVer[1] +
                   " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openplanning:");

    }
  }

  ## Checking for openComInterne product
  if("Communication Interne" >< rcvRes)
  {
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Cominterne
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_ComInterne",
                value:tmp_version);
      security_note(data:"Open ComInterne version " + openVer[1] +
                " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:opencominterne:");

    }
  }

  ## Checking for openCimetiere product
  if(">opencimetiere" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Cimetiere
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Cimetiere",
                value:tmp_version);
      security_note(data:"Open Cimetiere version " + openVer[1] +
                " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:opencimetiere:");

    }
  }

  ## Checking for openRegistreCIL product
  if(">Open Registre CIL&" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Registre CIL
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Registre_CIL",
                   value:tmp_version);
      security_note(data:"Open Registre CIL version " + openVer[1] +
               " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openregistrecil:");

     }
   }

  ## Checking for openFoncier product
  if(">openFoncier<" >< rcvRes || "Fonciere" >< rcvRes)
  {
    openVer = eregmatch(pattern:"Version&nbsp;([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Foncier
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Foncier",
                value:tmp_version);
      security_note(data:"Open Foncier version " + openVer[1] +
                " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openfoncier:");

    }

    openVer = eregmatch(pattern:">version ((beta)?.?([0-9.]+))", string:rcvRes);
    openVer[1] = ereg_replace(pattern:" ", string:openVer[1], replace:".");
    if(openVer[1] != NULL)
    {
      ## Set the version of Open Foncier
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Foncier",
                value:tmp_version);
      security_note(data:"Open Foncier version " + openVer[1] +
                " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:openfoncier:");

    }
  }
}

## Checking for the Opencatalogue product
foreach dir (make_list("/openmairie_catalogue", "/Openmairie_Catalogue", cgi_dirs()))
{
  ## Send and Recieve the response
  sndReq = http_get(item:string(dir , "/doc/catalogue.html"), port:openPort);
  rcvRes = http_send_recv(port:openPort, data:sndReq);

  ## Confirm the product
  if("OPENCATALOGUE" >< rcvRes || "[Cc]atalogue" >< rcvRes)
  {
    sndReq = http_get(item:string(dir , "/index.php"), port:openPort);
    rcvRes = http_send_recv(port:openPort, data:sndReq);

    ## Grep for version
    openVer = eregmatch(pattern:"> V e r s i o n ([0-9.]+)", string:rcvRes);
    if(openVer[1] != NULL)
    {
      ## Set the version of Opencatalogue
      tmp_version = openVer[1] + " under " + dir;
      set_kb_item(name:"www/" + openPort + "/OpenMairie/Open_Catalogue",
                value:tmp_version);
      security_note(data:"Open Catalogue version " + openVer[1] +
                " running at location " + dir + " was detected on the host");

      ## build cpe and store it as host_detail
      register_cpe(tmpVers:tmp_version, tmpExpr:"^([0-9.]+)", tmpBase:"cpe:/a:openmairie:opencatalogue:");

    }
  }
}
