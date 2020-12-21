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

    // helper to trigger success alert
    function success(msg, link) {
        loadingBar(100);

        // return the link to the report back to the user
        var link = url + link;
        var link_href = "<a href='" + link + "'>" + link + "</a>";
        newAlert(msg + " View the report here: " + link_href);
    }

    // connect to the socket.io server
    var ws_scheme = window.location.protocol;
    var url = ws_scheme + "//" + document.domain;
    if (location.port != "") {
        url = url.concat(":" + location.port);
    }

    var socket = io.connect(url);

    // once file is uploaded and page reloaded, check if message has changed, and if so,
    // create a loading bar and start the analysis workflow!
    // TODO: maybe kinda hacky, is there a better way?
    if ($("#message").text().indexOf("Successfully uploaded!") > -1) {
 	    loadingBar(0);
        socket.emit("identify");
    }


    socket.on("identify_reply", function(resp) {

        // if an existing entry is found, exit early
        if (resp["link"]) {
            success("Found existing artifact!", resp["link"])
            return
        }

        var header = "Packer Detection";
        if (resp["continue"] != false) {
 	        loadingBar(20);
            socket.emit("unpack");
        } else {
            newAlert("Cannot continue execution, unable to identify packer.");
        }
    });


    socket.on("unpack_reply", function(resp) {
        var header = "Executable Unpacking";
        if (resp["continue"]) {
            loadingBar(40);
            socket.emit("decompile");
        } else {
            newAlert("Cannot continue execution, error during unpacking.");
        }
    });


    socket.on("decompile_reply", function(resp) {
        var header = "Bytecode Decompilation";
        if (resp["continue"]) {
            loadingBar(60);
            socket.emit("sast");
        } else {
            newAlert("Cannot continue execution, failed during decompilation.");
        }
    });


    socket.on("sast_reply", function(resp) {
        loadingBar(80);
        socket.emit("finalize");
    });


    socket.on("finalize_reply", function(resp) {
        success("Done reverse engineering!", resp["link"])
    });
});
