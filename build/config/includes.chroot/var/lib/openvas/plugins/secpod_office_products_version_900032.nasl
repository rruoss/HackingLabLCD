###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_office_products_version_900032.nasl 42 2013-11-04 19:41:32Z jan $#
#
# MS Office Products Version Detection
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Retrieving Version from file (Removed old method and updated with GetVer).
# - By Chandan S <schandan@secpod.com> 10:46:00 2009-04-24
#
# Updated to include detect mechanism for Word Viewer and Word Converter - Sharath S
#
# Updated to include detect mechanism for Excel Viewer - Sharath S
#
# Updated to include detect mechanism for Power Point Viewer - Sharath S
#
# Updated to include detect mechanism for Office Publisher - Sharath S
#
# Updated to include detect mechanism for Office Outlook
#  - By Antu Sanadi <santu@secpod.com> On 2009/10/14
#
# Updated to include detect mechanism for Office Groove and Office Compatibility Pack
#  - By Sharath S <sharaths@secpod.com> On 2009-10-20 #5269
#
# Updated to include detect mechanism for Office Visio Viewer 2007
#  - By Sharath S <sharaths@secpod.com> On 2009-10-29 #5269
#
# Updated to check office installtion by adding registrty key check
#  - By Antu Sanadi <santu@secpod.com> on 2010-03-10 #7621
#
# Updated By : Antu Sanadi <santu@secpod.com> on 2012-02-15
#  - Updated to detect Microsoft Office PowerPoint Viewer
#  - Updated to detect Microsoft Office Visio Viewer 2010
#
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
################################################################################

include("revisions-lib.inc");
tag_summary = "Retrieve the version of MS Office products from file and
  sets KB.";

if(description)
{
  script_id(900032);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 42 $");
  script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:41:32 +0100 (Mo, 04. Nov 2013) $");
  script_tag(name:"creation_date", value:"2008-08-19 14:38:55 +0200 (Tue, 19 Aug 2008)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"risk_factor", value:"None");
  script_name("MS Office Products Version Detection");
  desc = "
  Summary:
  " + tag_summary;
  script_description(desc);
  script_summary("Determines the version of Microsoft Office products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl", "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_smb_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900032";
SCRIPT_DESC = "MS Office Products Version Detection";

WORDVIEW_LIST = make_list(" ^(9\..*)", "cpe:/a:microsoft:office_word_viewer:2000",
                          "^(10\..*)", "cpe:/a:microsoft:office_word_viewer:2002",
                          "^(11\..*)", "cpe:/a:microsoft:office_word_viewer:2003",
                          "^(12\..*)", "cpe:/a:microsoft:office_word_viewer:2007",
                          "^(14\..*)", "cpe:/a:microsoft:office_word_viewer:2010",
                          "^(15\..*)", "cpe:/a:microsoft:office_word_viewer:2013");
WORDVIEW_MAX = max_index(WORDVIEW_LIST);

XLVIEW_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_excel_viewer:2000",
                        "^(10\..*)", "cpe:/a:microsoft:office_excel_viewer:2002",
                        "^(11\..*)", "cpe:/a:microsoft:office_excel_viewer:2003",
                        "^(12\..*)", "cpe:/a:microsoft:office_excel_viewer:2007",
                        "^(14\..*)", "cpe:/a:microsoft:office_excel_viewer:2010",
                        "^(15\..*)", "cpe:/a:microsoft:office_excel_viewer:2013");
XLVIEW_MAX = max_index(XLVIEW_LIST);

PPVIEW_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2000",
                        "^(10\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2002",
                        "^(11\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2003",
                        "^(12\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2007",
                        "^(14\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2010",
                        "^(15\..*)", "cpe:/a:microsoft:office_powerpoint_viewer:2013");
PPVIEW_MAX = max_index(PPVIEW_LIST);

VISIO_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:visio_viewer:2000",
                       "^(10\..*)", "cpe:/a:microsoft:visio_viewer:2002",
                       "^(11\..*)", "cpe:/a:microsoft:visio_viewer:2003",
                       "^(12\..*)", "cpe:/a:microsoft:visio_viewer:2007",
                       "^(14\..*)", "cpe:/a:microsoft:visio_viewer:2010",
                       "^(15\..*)", "cpe:/a:microsoft:visio_viewer:2013");
VISIO_MAX = max_index(VISIO_LIST);

WORD_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_word:2000",
                      "^(10\..*)", "cpe:/a:microsoft:office_word:2002",
                      "^(11\..*)", "cpe:/a:microsoft:office_word:2003",
                      "^(12\..*)", "cpe:/a:microsoft:office_word:2007",
                      "^(14\..*)", "cpe:/a:microsoft:office_word:2010",
                      "^(15\..*)", "cpe:/a:microsoft:office_word:2013");
WORD_MAX = max_index(WORD_LIST);

EXCEL_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_excel:2000",
                       "^(10\..*)", "cpe:/a:microsoft:office_excel:2002",
                       "^(11\..*)", "cpe:/a:microsoft:office_excel:2003",
                       "^(12\..*)", "cpe:/a:microsoft:office_excel:2007",
                       "^(14\..*)", "cpe:/a:microsoft:office_excel:2010",
                       "^(15\..*)", "cpe:/a:microsoft:office_excel:2013");
EXCEL_MAX = max_index(EXCEL_LIST);

ACCESS_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:access:2000",
                        "^(10\..*)", "cpe:/a:microsoft:access:2002",
                        "^(11\..*)", "cpe:/a:microsoft:access:2003",
                        "^(12\..*)", "cpe:/a:microsoft:access:2007",
                        "^(14\..*)", "cpe:/a:microsoft:access:2010",
                        "^(15\..*)", "cpe:/a:microsoft:access:2013");
ACCESS_MAX = max_index(ACCESS_LIST);

POWERPNT_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_powerpoint:2000",
                          "^(10\..*)", "cpe:/a:microsoft:office_powerpoint:2002",
                          "^(11\..*)", "cpe:/a:microsoft:office_powerpoint:2003",
                          "^(12\..*)", "cpe:/a:microsoft:office_powerpoint:2007",
                          "^(14\..*)", "cpe:/a:microsoft:office_powerpoint:2010",
                          "^(15\..*)", "cpe:/a:microsoft:office_powerpoint:2013");
POWERPNT_MAX = max_index(POWERPNT_LIST);

OUTLOOK_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:outlook:2000",
                         "^(10\..*)", "cpe:/a:microsoft:outlook:2002",
                         "^(11\..*)", "cpe:/a:microsoft:outlook:2003",
                         "^(12\..*)", "cpe:/a:microsoft:outlook:2007",
                         "^(14\..*)", "cpe:/a:microsoft:outlook:2010",
                         "^(15\..*)", "cpe:/a:microsoft:outlook:2013");
OUTLOOK_MAX = max_index(OUTLOOK_LIST);

PUBLISHER_LIST = make_list( "^(9\..*)", "cpe:/a:microsoft:office_publisher:2000",
                           "^(10\..*)", "cpe:/a:microsoft:office_publisher:2002",
                           "^(11\..*)", "cpe:/a:microsoft:office_publisher:2003",
                           "^(12\..*)", "cpe:/a:microsoft:office_publisher:2007",
                           "^(14\..*)", "cpe:/a:microsoft:office_publisher:2010",
                           "^(15\..*)", "cpe:/a:microsoft:office_publisher:2013");
PUBLISHER_MAX = max_index(PUBLISHER_LIST);

## functions for script
function register_cpe(tmpVers, tmpExpr, tmpBase){

   local_var cpe;
   ## build cpe and store it as host_detail
   cpe = build_cpe(value:tmpVers, exp:tmpExpr, base:tmpBase);
   if(!isnull(cpe))
      register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);
}

## start script
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Office")){
  exit(0);
}

# Word Viewer
wordviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                   "\App Paths\wordview.exe", item:"Path");
if(wordviewFile)
{
  wordviewFile += "\WORDVIEW.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordviewFile);
  wview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordviewFile);
  wordviewVer = GetVer(file:wview, share:share);
  if(wordviewVer){
    set_kb_item(name:"SMB/Office/WordView/Version", value:wordviewVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < WORDVIEW_MAX-1; i = i + 2) {

       register_cpe(tmpVers:wordviewVer, tmpExpr:WORDVIEW_LIST[i], tmpBase:WORDVIEW_LIST[i+1]);
    }
  }
}

# Excel Viewer (or) PowerPoint Viewer (or) Office Compatibility Pack
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(registry_key_exists(key:key))
{
foreach item (registry_enum_keys(key:key))
{
  if("Microsoft Office Excel Viewer" ><
     registry_get_sz(key:key + item, item:"DisplayName"))
  {
    xlviewVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(xlviewVer != NULL)
    {
      xlviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                   item:"ProgramFilesDir");
      if(xlviewVer =~ "^11(\..*)")
        xlviewFile += "\Microsoft Office\Office11\XLVIEW.EXE";
      else if(xlviewVer =~ "^12(\..*)")
        xlviewFile += "\Microsoft Office\Office12\XLVIEW.EXE";
      else if(xlviewVer =~ "^14(\..*)")
         xlviewFile += "\Microsoft Office\Office14\XLVIEW.EXE";
      else if(xlviewVer =~ "^15(\..*)")
         xlviewFile += "\Microsoft Office\Office15\XLVIEW.EXE";

      if(xlviewFile != NULL)
      {
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:xlviewFile);
        xlview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:xlviewFile);
        xlviewVer = GetVer(file:xlview, share:share);
        if(xlviewVer != NULL){
          set_kb_item(name:"SMB/Office/XLView/Version", value:xlviewVer);

          ## build cpe and store it as host_detail  
          for (i = 0; i < XLVIEW_MAX-1; i = i + 2) {

            register_cpe(tmpVers:xlviewVer, tmpExpr:XLVIEW_LIST[i], tmpBase:XLVIEW_LIST[i+1]);
          }
        }
      }
    }
  }
  else if("Microsoft Office PowerPoint Viewer" >< registry_get_sz(key:key + item, item:"DisplayName")||
          "Microsoft PowerPoint Viewer" >< registry_get_sz(key:key + item, item:"DisplayName")) 
  {
    pptviewVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(pptviewVer != NULL)
    {
      ppviewFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                   item:"ProgramFilesDir");
      if(pptviewVer =~ "^11(\..*)")
        ppviewFile += "\Microsoft Office\PowerPoint Viewer\PPTVIEW.exe";
      else if(pptviewVer =~ "^12(\..*)")
        ppviewFile += "\Microsoft Office\Office12\PPTVIEW.exe";
      else if (pptviewVer =~ "^14(\..*)")
        ppviewFile += "\Microsoft Office\Office14\PPTVIEW.exe";
      else if (pptviewVer =~ "^15(\..*)")
        ppviewFile += "\Microsoft Office\Office15\PPTVIEW.exe";

      if(ppviewFile != NULL)
      {
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppviewFile);
        pptview = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppviewFile);
        pptviewVer = GetVer(file:pptview, share:share);
        if(pptviewVer != NULL){
          set_kb_item(name:"SMB/Office/PPView/Version", value:pptviewVer);

          ## build cpe and store it as host_detail  
          for (i = 0; i < PPVIEW_MAX-1; i = i + 2) {

             register_cpe(tmpVers:pptviewVer, tmpExpr:PPVIEW_LIST[i], tmpBase:PPVIEW_LIST[i+1]);
          }
        }
      }
    }
  }
  else if("Compatibility Pack" ><
     registry_get_sz(key:key + item, item:"DisplayName"))
  {
    cPackVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(cPackVer != NULL){
      set_kb_item(name:"SMB/Office/ComptPack/Version", value:cPackVer);

      ## build cpe and store it as host detail
      register_cpe(tmpVers:cPackVer,tmpExpr:"^(12\..)*",tmpBase:"cpe:/a:microsoft:compatibility_pack_word_excel_powerpoint:2007:");
    }
  }
}
}

# Office Groove
groovePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\GROOVE.EXE", item:"Path");
if(groovePath != NULL)
{
  groovePath += "\GROOVE.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:groovePath);
  groove = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:groovePath);
  grooveVer = GetVer(file:groove, share:share);
  if(grooveVer != NULL){
    set_kb_item(name:"SMB/Office/Groove/Version", value:grooveVer);

    ## build cpe and store it as host detail
    register_cpe(tmpVers:grooveVer,tmpExpr:"^(12\..*)",tmpBase:"cpe:/a:microsoft:office_groove:2007:");
  }
}

# Office Power Point Convertes
if(registry_key_exists(key:"SOFTWARE\Microsoft\Office"))
{
  ppcnvFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(ppcnvFile)
  {
    ppcnvFile += "\Microsoft Office\Office12\PPCNVCOM.exe";
    share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:ppcnvFile);
    ppfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:ppcnvFile);
    ppcnvVer = GetVer(file:ppfile, share:share);
    if(ppcnvVer){
      set_kb_item(name:"SMB/Office/PowerPntCnv/Version", value:ppcnvVer);

      ## build cpe and store it as host detail
      register_cpe(tmpVers:ppcnvVer,tmpExpr:"^(12\..)",tmpBase:"");
    }
  }
}


visiovVer = "";
visioPath = "";
exePath = "";
# Office Visio Viewer
visioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"ProgramFilesDir");
if(visioPath)
{
  foreach path (make_list("Office12", "Office14", "Office15"))
  {
    ## Get Version from msptls.dll
    exePath = visioPath + "\Microsoft Office\" + path ;
    if(exePath)
    {
     visiovVer = fetch_file_version(sysPath:exePath, file_name:"Vpreview.exe");
     if(visiovVer)
     {
      set_kb_item(name:"SMB/Office/VisioViewer/Ver", value:visiovVer);

      ## build cpe and store it as host_detail  
      for (i = 0; i < VISIO_MAX-1; i = i + 2) {

         register_cpe(tmpVers:visiovVer, tmpExpr:VISIO_LIST[i], tmpBase:VISIO_LIST[i+1]);
      }
    }
  }
 }
}

# To Conform Office Installation
if(!get_kb_item("MS/Office/Ver") && !registry_key_exists(key:"SOFTWARE\Microsoft\Office" )){
  exit(0);
}

# Office Word
wordFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\App Paths\Winword.exe", item:"Path");
if(wordFile)
{
  wordFile += "\winword.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordFile);
  word = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordFile);
  wordVer = GetVer(file:word, share:share);
  if(wordVer){
    set_kb_item(name:"SMB/Office/Word/Version", value:wordVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < WORD_MAX-1; i = i + 2) {

       register_cpe(tmpVers:wordVer, tmpExpr:WORD_LIST[i], tmpBase:WORD_LIST[i+1]);
    }
  }
}

# Office Excel
excelFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\Excel.exe", item:"Path");
if(excelFile)
{
  excelFile += "\excel.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:excelFile);
  excel =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:excelFile);
  excelVer = GetVer(file:excel, share:share);
  if(excelVer){
    set_kb_item(name:"SMB/Office/Excel/Version", value:excelVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < EXCEL_MAX-1; i = i + 2) {

       register_cpe(tmpVers:excelVer, tmpExpr:EXCEL_LIST[i], tmpBase:EXCEL_LIST[i+1]);
    }
  }
}

# Office Access
accessFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\MSACCESS.exe", item:"Path");
if(accessFile)
{
  accessFile += "\msaccess.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:accessFile);
  access = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:accessFile);
  accessVer = GetVer(file:access, share:share);
  if(accessVer){
    set_kb_item(name:"SMB/Office/Access/Version", value:accessVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < ACCESS_MAX-1; i = i + 2) {

       register_cpe(tmpVers:accessVer, tmpExpr:ACCESS_LIST[i], tmpBase:ACCESS_LIST[i+1]);
    }
  }
}

# Office PowerPoint
powerpointFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\App Paths\PowerPnt.exe", item:"Path");
if(powerpointFile)
{
  powerpointFile += "\powerpnt.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:powerpointFile);
  power = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:powerpointFile);
  powerPptVer = GetVer(file:power, share:share);
  if(powerPptVer){
    set_kb_item(name:"SMB/Office/PowerPnt/Version", value:powerPptVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < POWERPNT_MAX-1; i = i + 2) {

       register_cpe(tmpVers:powerPptVer, tmpExpr:POWERPNT_LIST[i], tmpBase:POWERPNT_LIST[i+1]);
    }
  }
}

# Office Word Converter
wordcnvFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
if(wordcnvFile)
{
  wordcnvFile += "\Microsoft Office\Office12\Wordconv.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wordcnvFile);
  word  = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wordcnvFile);
  wordcnvVer = GetVer(file:word, share:share);
   if(wordcnvVer){
    set_kb_item(name:"SMB/Office/WordCnv/Version", value:wordcnvVer);

    ## build cpe and store it as host detail
    register_cpe(tmpVers:wordcnvVer,tmpExpr:"^(12\..*)",tmpBase:"");
  }
}

# Office Excel Converter
xlcnvFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"ProgramFilesDir");
if(xlcnvFile)
{
  xlcnvFile += "\Microsoft Office\Office12\excelcnv.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:xlcnvFile);
  xlfile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:xlcnvFile);
  xlcnvVer = GetVer(file:xlfile, share:share);
  if(xlcnvVer){
    set_kb_item(name:"SMB/Office/XLCnv/Version", value:xlcnvVer);

    ## build cpe and store it as host detail
    register_cpe(tmpVers:xlcnvVer,tmpExpr:"^(12\..*)",tmpBase:"");
  }
}

# Office Publisher
pubFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\MSPUB.EXE", item:"Path");
if(pubFile)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:pubFile);
  pub = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:pubFile + "\MSPUB.exe");
  pubVer = GetVer(file:pub, share:share);
  if(pubVer){
    set_kb_item(name:"SMB/Office/Publisher/Version", value:pubVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < PUBLISHER_MAX-1; i = i + 2) {

       register_cpe(tmpVers:pubVer, tmpExpr:PUBLISHER_LIST[i], tmpBase:PUBLISHER_LIST[i+1]);
    }
  }
}

# Office outlook
outlookFile = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                              "\App Paths\OUTLOOK.EXE", item:"Path");
if(outlookFile)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:outlookFile);
  outlookFile = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                             string:outlookFile + "\OUTLOOK.EXE");
  outlookVer = GetVer(file:outlookFile, share:share);
  if(outlookVer){
    set_kb_item(name:"SMB/Office/Outloook/Version", value:outlookVer);

    ## build cpe and store it as host_detail  
    for (i = 0; i < OUTLOOK_MAX-1; i = i + 2) {

       register_cpe(tmpVers:outlookVer, tmpExpr:OUTLOOK_LIST[i], tmpBase:OUTLOOK_LIST[i+1]);
    }
  }
}
