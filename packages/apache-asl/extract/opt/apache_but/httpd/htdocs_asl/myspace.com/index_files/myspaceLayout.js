// JavaScript Document
// Used by the CSS layout page to adjust the height and width of columns depending on content.

function adjustHeight() {
	
	// Get the height of nav and content
	var navHeight = document.getElementById('nav').offsetHeight;
	var contentHeight = document.getElementById('content').offsetHeight;
	
	// Set the height of the main container to the same as the tallest column.
	document.getElementById('main').style.height = Math.max(navHeight, contentHeight) + 50;
}


function adjustLayout(n, c) {

	// Get the height of nav and content
	var navHeight = document.getElementById('nav').offsetHeight;
	var contentHeight = document.getElementById('content').offsetHeight;
	
	// Set the height of the main container to the same as the tallest column.
	document.getElementById('main').style.height = Math.max(navHeight, contentHeight);
	
	// This needs to be used when the done when using relative positioning
	// Check if nav height is taller than content height
	//if(navHeight > contentHeight) {
		// sets height of main container to nav height plus 100 for IE
		//document.getElementById('main').style.height = navHeight;
	//}
	
	// Get width of nav, content, and main
	var navWidth = document.getElementById('nav').offsetWidth;
	var contentWidth = document.getElementById('content').offsetWidth;
	var wrapWidth = document.getElementById('wrap').offsetWidth;
	var wrapWidthFlag = false;
			
	if(navWidth > wrapWidth * n) {
		// pushes the content column to the right.
		wrapWidthFlag = true;
	}
	
	if((contentWidth > wrapWidth * c) || wrapWidthFlag == true)
	{
		// expands the width of the wrap.
		if ((navWidth + contentWidth) > 800)
		{
			document.getElementById('wrap').style.width =  (navWidth + contentWidth + (wrapWidth * 0.03)) * 1.03;
			
			if(navigator.appName == 'Microsoft Internet Explorer')
			{
				document.getElementById('content').style.left = navWidth + (0.02 * wrapWidth);
				document.getElementById('nav').style.width = navWidth;
				document.getElementById('content').style.width = contentWidth;
			}
			else
			{	
				document.getElementById('content').style.left = document.getElementById('nav').offsetWidth + (0.02 * wrapWidth);
			}
		}
	}
}
