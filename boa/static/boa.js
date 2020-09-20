$(document).ready(function() {
    // automatically submit after uploading a form
    $("#file").change(function() {
        $("#form").submit();
    });


    // initializes a new status table to display results in
    function initTable() {
        $("#statustable").append(`
        <br>
        <table id="table" class="table order-list">
 	       <thead>
 	   	<tr>
                <td><p style="font-size: 10.5px;">Event</p></td>
                <td><p style="font-size: 10.5px;">Status</p></td>
                <td><p style="font-size: 10.5px;">Output</p></td>
 	   	</tr>
 	       </thead>
 	       <tbody>
 	   	    <tr>
 	   	    </tr>
 	       </tbody>
 	   </table>`)
    }

    // given an initialized status table, append a new row with a key and value
    function updateTable(key, stat, msg) {
        var newRow = $("<tr>");
        var cols = "";
        cols += "<td><p style='font-size: 8.5px; font-weight: normal;'>" + key + "</p></td>"
        if (stat) {
            cols += "<td>✔️</td>"
        } else {
            cols += "<td>X</td>"
        }
        cols += "<td><p style='font-size: 8.5px; font-weight: normal;'>" + msg + "</p></td>"
        newRow.append(cols)
        $("table.order-list").append(newRow);
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
                <div class="progress-bar progress-bar-striped bg-white" role="progressbar" style="width: ` + value +
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
            <p style="font-size: 10.5px;">` + msg + `</p>
        </div>
        <br>
        `);
    }

    // helper to trigger success alert
    function success(msg, link) {
        // update the loading bar to completion
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
        initTable();
        socket.emit("identify");
    }


    socket.on("identify_reply", function(resp) {

        // if an existing entry is found, exit early
        if (resp["link"]) {
            success("Found existing artifact!", resp["link"])
        }

        var header = "Packer Detection";
        if (resp["continue"] != false) {
            // update the loading bar
 	       loadingBar(20);

            // append a new row to the status table
            msg = "Identified: " + resp["packer"]
            updateTable(header, true, msg);

            // continue execution and actually unpack
            socket.emit("unpack");
        } else {
            updateTable(header, false, "Unknown Packer");
            newAlert("Cannot continue execution, unable to identify packer.");
        }
    });


    socket.on("unpack_reply", function(resp) {
        var header = "Executable Unpacking";
        if (resp["continue"]) {
            // update the loading bar
            loadingBar(40);

            // append a row with the number of decompilable bytecode files recovered
            msg = resp["extracted"] + " .pyc bytecode files extracted"
            updateTable(header, true, msg);

            // continue execution and start decompiling the relevant bytecode
            socket.emit("decompile");
        } else {
            updateTable(header, false, resp["error"]);
            newAlert("Cannot continue execution, error during unpacking.");
        }
    });


    socket.on("decompile_reply", function(resp) {
        var header = "Bytecode Decompilation";
        if (resp["continue"]) {
            // update the loading bar
            loadingBar(60);

            // append a row with number of Python source files recovered
            msg = resp["src_files"] + " relevant source files recovered"
            updateTable(header, true, msg);

            // TODO: add additional row for patching info

            socket.emit("sast");
        } else {
            updateTable(header, false, resp["error"]);
            newAlert("Cannot continue execution, failed during decompilation.");
        }
    });


    socket.on("sast_reply", function(resp) {
        var header = "Static Analysis";

        // update the loading bar
        loadingBar(80);

        // append a row with number of Python source files recovered
        if (!resp["error"]) {
            msg = resp["issues_found"] + " potential security issues found"
            updateTable(header, true, msg);

        // displaying with errors is fine, continue anyway
        } else {
            updateTable(header, false, resp["error"]);
        }

        // finalize execution and generate report
        socket.emit("finalize");
    });


    socket.on("finalize_reply", function(resp) {
        success("Done reverse engineering!", resp["link"])
    });
});
