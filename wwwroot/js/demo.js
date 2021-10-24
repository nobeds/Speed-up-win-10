$(document).ready(function(){

	$('#color-schemes li a').click(function(){

		var num = $(this).parent().index() + 1;
		$(this).parents('ul').find('a').removeClass('current');

		$(this).addClass('current');
		if( $('head link[href*="css/color-schemes/color-scheme"]').length > 0 ) {
			$('head link[href*="css/color-schemes/color-scheme"]').attr('href', 'css/color-schemes/color-scheme-'+num+'.css');
		} else {
			$('head').append('<link rel="stylesheet" href="css/color-schemes/color-scheme-'+num+'.css">');
		}

		return false;
	});
});