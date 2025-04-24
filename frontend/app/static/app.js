$(document).ready(function(){
    console.log("Loaded!")
    $.get( "/api/auth/check", function( data ) {
        console.log(data);
        if (data.redirect === true) {
            window.location.replace(data.url);
        }
    });
});
