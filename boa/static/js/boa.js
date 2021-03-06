$(document).ready(function() {
    // automatically submit after uploading a form
    $("#file").change(function() {
        $("#form").submit();
    });


    // initialize an interface to intercept server-sent events from redis pubsub
    var source = new EventSource("/stream");

    // listen for events and update table accordingly
    source.addEventListener("events", function(event) {
        var data = JSON.parse(event.data);
        
        // handle error if task failed
        if data["error"] != null {
            newAlert("Failed!");
        } else {
            newAlert(data.toSource())
        }
    }, false);


    // create or update the current job
    function updateJob(jobId) {
        // TODO
    }

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
});
