###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_java_prdts_detect_win.nasl 43 2013-11-04 19:51:40Z jan $
#
# Sun Java Products Version Detection (Win)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800383";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 43 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:51:40 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"detection", value:"registry version check");
  script_name("Sun Java Products Version Detection (Win)");

  tag_summary =
  "Detection of installed version of Java Products.

The script logs in via smb, searches for Java Products in the registry and
gets the version from 'Version' string in registry";

  desc = "
  Summary:
  " + tag_summary;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_summary("Detection of installed version of Java Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

## Variable initialization
keys = "";
jrVer = "";
jdVer = "";
wsVer = "";
jreKey = "";
jreVer = "";
jdkKey = "";
jdkVer = "";
JreTmpkey = "";
JdkTmpkey = "";

# Java Web-Start
wsVer = registry_get_sz(key:"SOFTWARE\JavaSoft\Java Web Start",
                        item:"CurrentVersion");
if(wsVer != NULL){
  set_kb_item(name:"Sun/Java/WebStart/Win/Ver", value:wsVer);
}

# Java Runtime Environment
jreKey = "SOFTWARE\JavaSoft\Java Runtime Environment";
if(registry_key_exists(key:jreKey))
{
  keys = registry_enum_keys(key:jreKey);
  foreach item (keys)
  {
    jreVer = eregmatch(pattern:"([0-9.]\.[0-9]\.[0-9._]+)", string:item);
    if(jreVer[1])
    {
      JreTmpkey =  jreKey + "\\"  + jreVer[1];
      if(!registry_key_exists(key:JreTmpkey)){
       path = "Could not find the install path from registry";
      }
      else
      {
         path = registry_get_sz(key:JreTmpkey, item:"JavaHome");
         if(!path){
           path = "Could not find the install path from registry";
         }
         chk_path = registry_get_sz(key:JreTmpkey, item:"RuntimeLib");
      }
    }

    if(chk_path) {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:chk_path);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:chk_path);
      chk_size = get_file_size(share:share, file:file);
    } else {
      chk_size = 1;
    }

    if(jreVer[1] != NULL && chk_size > 0)
    {
      set_kb_item(name:"Sun/Java/JRE/Win/Ver", value:jreVer[1]);
      jrVer = ereg_replace(pattern:"_|-", string:jreVer[1], replace: ".");

      if(version_is_less(version:jrVer, test_version:"1.4.2.38") ||
         version_in_range(version:jrVer, test_version:"1.5", test_version2:"1.5.0.33") ||
         version_in_range(version:jrVer, test_version:"1.6", test_version2:"1.6.0.18"))
      {

        ## set the CPE "cpe:/a:sun:jre:" if JRE belongs the above version range
        ## (Before Oracles acquisition of Sun)
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:jreVer[1], exp:"^([0-9._]+)", base:"cpe:/a:sun:jre:");
        if(isnull(cpe))
          cpe="cpe:/a:sun:jre";

        register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
        log_message(data: build_detection_report(app:"Sun Java JRE ",
                                                 version:jreVer[1],
                                                 install: path,
                                                 regpath:JreTmpkey,
                                                 cpe:cpe,
                                                 concluded:jreVer[1]));

      }
      else
      {
        ## set the CPE "cpe:/a:oracle:jre:" for recent versions of JRE
        ## (After Oracles acquisition of Sun)
        cpe = build_cpe(value:jreVer[1], exp:"^([0-9._]+)", base:"cpe:/a:oracle:jre:");
        if(isnull(cpe))
           cpe= "cpe:/a:oracle:jre";

        register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
        log_message(data: build_detection_report(app:"Oracle Java JRE ",
                                                 version:jreVer[1],
                                                 install: path,
                                                 regpath:JreTmpkey,
                                                 cpe:cpe,
                                                 concluded:jreVer[1]));
      }
    }
  }
}

# Java Development Kit
jdkKey = "SOFTWARE\JavaSoft\Java Development Kit";
if(registry_key_exists(key:jdkKey))
{
  keys = registry_enum_keys(key:jdkKey);
  foreach item (keys)
  {
    jdkVer = eregmatch(pattern:"([0-9.]\.[0-9]\.[0-9._]+)", string:item);
    if(jdkVer[1])
    {
      JdkTmpkey =  jdkKey + "\\"  + jdkVer[1];
      if(!registry_key_exists(key:JdkTmpkey)){
        path = "Could not find the install path from registry";
      }
      else
      {
        path = registry_get_sz(key:JdkTmpkey, item:"JavaHome");
        if(!path){
          path = "Could not find the install path from registry";
        }
        chk_path = registry_get_sz(key:JreTmpkey, item:"RuntimeLib");
      }
    }

    if(chk_path) {
      share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:chk_path);
      file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:chk_path);
      chk_size = get_file_size(share:share, file:file);
    } else {
      chk_size = 1;
    }

    if(jdkVer[1] != NULL && chk_size > 0)
    {
      set_kb_item(name:"Sun/Java/JDK/Win/Ver", value:jdkVer[1]);
      jdVer = ereg_replace(pattern:"_|-", string:jdkVer[1], replace: ".");
      if(version_is_less(version:jdVer, test_version:"1.4.2.38") ||
         version_in_range(version:jdVer, test_version:"1.5", test_version2:"1.5.0.33") ||
         version_in_range(version:jdVer, test_version:"1.6", test_version2:"1.6.0.18"))
      {

        ## set the CPE "cpe:/a:sun:jdk:" if JDK belongs the above version range
        ## (Before Oracles acquisition of Sun)
        ## build cpe and store it as host_detail
        cpe = build_cpe(value:jdkVer[1], exp:"^([0-9._]+)", base:"cpe:/a:sun:jdk:");
        if(isnull(cpe))
          cpe= "cpe:/a:sun:jdk";

        register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
        log_message(data: build_detection_report(app:"Sun Java JDK ",
                                                 version:jdkVer[1],
                                                 install: path,
                                                 regpath:JdkTmpkey,
                                                 cpe:cpe,
                                                 concluded:jdkVer[1]));
      }
      else
      {
         ## set the CPE "cpe:/a:oracle:jdk:" for recent versions of JDK
         ## (After Oracles acquisition of Sun)
        cpe = build_cpe(value:jdkVer[1], exp:"^([0-9._]+)", base:"cpe:/a:oracle:jdk:");
        if(isnull(cpe))
           cpe="cpe:/a:oracle:jdk";

         register_product(cpe:cpe, location:path, nvt:SCRIPT_OID);
         log_message(data: build_detection_report(app:"Oracle Java JDK ",
                                                  version:jdkVer[1],
                                                  install: path,
                                                  regpath:JdkTmpkey,
                                                  cpe:cpe,
                                                  concluded:jdkVer[1]));
      }
    }
  }
}

# JRE for Windows IE
ieJavaKey = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer" +
                                "\AdvancedOptions\JAVA_SUN\SELECT",
                            item:"Text");
if(("Use JRE" || "Use Java") >< ieJavaKey)
{
  ieJavaVer =  ereg_replace(pattern:"Use (JRE.|Java.*v)([._0-9].*) for.*",
                            replace:"\2", string:ieJavaKey);
  if(ieJavaVer)
  {
    set_kb_item(name:"Sun/Java/JRE/Win/IE/Ver", value:ieJavaVer);
    log_message(data:"Sun Java JRE Windows IE version " + ieJavaVer +
                       " was detected on the host");
  }
}
