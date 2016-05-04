// https://www.quantcast.com/top-sites/PL
// all: 1019 URLs divided among PL, UK and US
var o = [];
jQuery("table.intl-top-sites").find("td.link > img[name]").each(function() {
    o.push({
        url: $(this).attr('name'),
        traffic: +$(this).parent().siblings("td.digit").text().replace(/,/g,"")
    });
});
