$(document).ready(function() {
    // automatically submit after uploading a form
    $("#file").change(function() {
        $("#form").submit();
    });


    // convenient helper to create or update a loading bar during the scan
    function loadingBar(value) {

        // if the loading bar exists, update its values
 	   if ($("#bar").length) {
           $("#bar").css("width", value + "%");
           $("#bar").attr("aria-valuenow", value);

        // otherwise create the bar
 	   } else {
            bar_html = `
            <div class="progress" id="progress">
                <div class="progress-bar progress-bar-striped" role="progressbar" style="width: ` + value +
            `%" aria-valuenow="` + value +
            `" aria-valuemin="0" aria-valuemax="100" id="bar">
                </div>
            </div>
            <br>
            `
            $("#progress").append(bar_html)
 	   }
    }


    // convenient helper to help create a new alert with a message
    function newAlert(msg) {
        $("#alerts").append(`
        <div class="alert alert-dark" role="alert">
            <p>` + msg + `</p>
        </div>
        <br>
        `);
    }

    // used to finalize the progress bar, and append an alert with the report link
    function success(msg, link) {
        loadingBar(100);
        var link = url + link;
        var link_href = "<a href='" + link + "'>" + link + "</a>";
        newAlert(msg + " View the report here: " + link_href);
    }
});
