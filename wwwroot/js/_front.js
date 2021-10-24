$(document).ready(function(){
	
	if( $('#sandglass').length > 0 ) {

		emptyTop();
		vertAlign($('#countdown-block'));

	}

	if( $('#countdown').length > 0 ) {

		var layout = '<div class="countdown-section"><div class="countdown-amount">{dn}</div><span class="sep">{sep}</span></div>'
				+'<div class="countdown-section"><div class="countdown-amount">{hnn}</div><span class="sep">{sep}</span></div>'
				+'<div class="countdown-section"><div class="countdown-amount">{mnn}</div><span class="sep">{sep}</span></div>'
				+'<div class="countdown-section secs"><div class="countdown-amount">{snn}</div></div>',
			countdate = new Date(SiteStartDate);

		$('#countdown').countdown({
			until: new Date() + 1,
			format: 'DHMS',
			layout: layout
		});
	}
	$('.show-section').click(function() {
		$(this).toggleClass('visible').parent().toggleClass('visible');
		$('body').toggleClass('sidemenu');
		return false;
	});

	if( $('#background-slideshow').length > 0 ) {
		$('#background-slideshow').kenburnsy({
			fullscreen: true
		});
	}

	if( $('#gmap').length > 0 ) {
		var opts = {
			div: '#gmap',
			el: '#gmap',
			lat: 40.751611, /* Latitude */
			lng: -73.979167, /* Longtitude */
			disableDefaultUI: true,
			styles: map_styles,
			scrollwheel: false
		};

		if( !$('#gmap').hasClass('streetview') )  {
			var gmap = new GMaps(opts);
		} else {
			var gmap = new GMaps.createPanorama(opts);
		}

		GMaps.geocode({
			address: gmap_address,
			callback: function(results, status) {
				if (status == 'OK') {
					var latlng = results[0].geometry.location;
					gmap.setCenter(latlng.lat(), latlng.lng());
					gmap.addMarker({
						lat: latlng.lat(),
						lng: latlng.lng()
					});
				}
			}
		});
	}

	if( $('#youtube-bg').length > 0 ) {
		$('#youtube-bg').tubular({
			videoId: youtube_bg_code,
			start: 0  // Starting position in seconds
		});
	}

	if( $('#local-video-bg').length > 0 ) {
		$('#local-video-bg').vide({
			mp4: "video/background-video.mp4", /* Local Video File Path */
		}, {
			muted: true
		});
	}

	if( $('#multi-color').length > 0 ) {
		$('#multi-color').animatedBG({
			colorSet: colorset,
			speed: 6000
		});
	}

	if( $('#side-menu').length > 0 ) {

		$('#menu li a').click(function() {
			var pane = $(this).attr('href'),
				timeout;
			$('body').removeClass('sidemenu');
			clearTimeout(timeout);
			$(this).parents('ul').find('.current').removeClass('current');
			$(this).addClass('current');
			$('.content-pane').fadeOut();
			$(pane).fadeIn(900, function(){
				$(this).find('.anim').css('visibility', 'visible').addClass('animated zoomIn');
				setTimeout(function(){
					$('#side-menu, #menu-show').removeClass('visible');
					$(pane).find('.animated').removeClass('animated');
				}, 300);
			});

			

			if(pane == '#') {
				$('#countdown-block').fadeIn();
				$('#side-menu, #menu-show').removeClass('visible');
			} else {
				$('#countdown-block').fadeOut();				
			}

			return false;
		});
	}

	/* Form Submiting */
	$('.form-submit').on('click', function(){
		"use strict";
		var form = $(this).parents('form');
		form.find('.form_item').removeClass('invalid');
		form.find('.error').remove();
		var post_data;
		var errors = formValidation(form),
			output;
		if( Object.keys(errors).length > 0 ) {
			showErrors(form, errors);
		} else {
			$(this).addClass('loading');
			if(form.attr('id') == 'contacts_form') {
					post_data = {
        			    'name'     : $('input[name=name]').val(),
        			    'email'    : $('input[name=email]').val(),
        			    'message'  : $('textarea[name=message]').val()
        			};

        		//Ajax post data to server
        		jQuery.post('contacts.php', post_data, function(response){	

        			$("#contacts_form .form_submit").removeClass('loading');

        		    if(response.type == 'error'){ //load json data from server and output message    
        		        output = '<div class="error_block">'+response.text+'</div>';
        		    } else{
        		        output = '<div class="success">'+response.text+'</div>';
        		        //reset values in all input fields
        		        $("#contacts_form .form_item").val('');
        		    }
        		    form.find('.form_row').slideUp();
        		    form.find(".form_results").hide().html(output).slideDown();
        		}, 'json');
    		}
		}
        
		
		if(form.attr('id') == 'contacts_form') {
			return false;
		}
	});

	$('#configurator .aside-inner').mCustomScrollbar({
		autoHideScrollbar: true,
		scrollbarPosition: 'outside'
	});

	$('.content-pane .pane-inner').each(function(){
		$(this).mCustomScrollbar({
			autoHideScrollbar: true,
			scrollbarPosition: 'outside'
		});
	});

	$('#preloader').fadeOut(500, function(){
		$(this).remove();
	});
});

function emptyTop() {
	$('#sandglass').removeClass('rotating');

	var intervalus = setInterval(function(){
		if( $('#sandglass .part-top').css('borderTopWidth').replace('px', '') <= 1 ) {
			clearInterval(intervalus);
			rotateClock();
			
		} else {
			var bdTop = $('#sandglass .part-top').css('borderTopWidth').replace('px', '') - 1,
				mleft = $('#sandglass .part-top').outerHeight() / 2;
			$('#sandglass .part-top').css({'borderTopWidth': bdTop, 'borderLeftWidth':bdTop* 0.58, 'borderRightWidth':bdTop* 0.58});
			$('#sandglass .part-bot').css('borderBottomWidth', 150-bdTop);
		}
	}, 150);
}

function rotateClock() {
	$('#sandglass').addClass('rotating');
	$('#sandglass .sand-part').removeAttr('style');

	setTimeout(function(){
		emptyTop()
	}, 800);
}

/* Vertical Alignment */
function vertAlign(elem) {
	"use strict";
	if(elem) {
		elem.css({
			'marginTop' : - elem.outerHeight()/2
		}).fadeIn(); 
	}
}

/* Validation Errors */
function showErrors(form, errors) {
	"use strict";
	var error_message = '';
	for(var i in errors) {
		if( errors[i] == 'empty' ) {
			var form_item = form.find($('#'+i)),
				form_item_name = form_item.attr('name').replace('_', ' ');
			form.find('#'+i).addClass('invalid').after('<div class="error">Field '+form_item_name+' is required</div>');
		} else {
			form.find('#'+i).after('<div class="error">You entered an invalid email</div>');
		}
	}
}

/* Forms Validation */
function formValidation(form) {
	"use strict";

	var error = {};

	if(form) {
		form.find('.form_item').each(function(){
			var $th = $(this);

			if( $th.val() != '' ) {
				if( $th.attr('type') == 'email' ) {
					var emailReg = /^([\w-\.]+@([\w-]+\.)+[\w-]{2,4})?$/;
					if( !emailReg.test( jQuery.trim($th.val()) ) ) {
						error[$th.attr('id')] = 'not_email';
					}
				}
			} else {				
				error[$th.attr('id')] = 'empty';
			}

		});
	}
	return error;
}