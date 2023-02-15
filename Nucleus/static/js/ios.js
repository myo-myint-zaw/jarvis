function selected_option(option) {
    let menu_options = {
        "1.1": "Configure host system parameters",
        "1.2": "Configure NTP",
        "1.3": "Configure motd and login Banner",
        "1.4": "Configure AAA",
        "1.5": "Configure SNMP",
        "1.6": "Configure System Logging",
        "2.1": "Configure STP",
        "2.2": "Configure Aggregation group",
        "2.3": "Configure L2 interfaces",
        "2.4": "Configure VLANs",
        "3.1": "Configure L3 interface IP",
        "3.2": "Configure HSRP",
        "3.3": "Configure VRRP",
        "3.4": "Configure OSPF",
        "3.5": "Configure OSPF for interfaces",
        "3.6": "Configure BFD",
        "3.7": "Configure BGP",
        "3.8": "Configure Static Route",
        "3.9": "Configure VRF"
    };
    let menu_option = document.getElementById("menu_option");
    menu_option.value = menu_option.title = menu_options[option];
    const x = document.getElementById("ios_menu");
    if (x.className.indexOf("w3-show") === -1) {
        x.className += " w3-show";
    }
    else {
        x.className = x.className.replace(" w3-show", "");
    }
}

function drop_menu(id_name) {
    const x = document.getElementById(id_name);
    if (x.className.indexOf("w3-show") === -1) {
        x.className += " w3-show";
    }
    else {
        x.className = x.className.replace(" w3-show", "");
    }
}

function get_template_file() {
    document.getElementById("template_file"
    ).innerHTML = "Template File: &nbsp;&nbsp;" + document.getElementById("deployment_file").files[0].name
}

function get_inventory_file() {
    document.getElementById("config_file"
    ).innerHTML = "Inventory File: &nbsp;&nbsp;" + document.getElementById("inventory_file").files[0].name
}

function execute_ios() {
    let menu_option = document.getElementById("menu_option").value;
    if (menu_option === "") {
        swal({
            title: "Menu option missing",
            text: "IOS Menu is not selected in Step 1",
            icon: "error"
        });
        return false;
    }
    let deployment_file = document.getElementById("deployment_file").files[0];
    if (deployment_file === undefined) {
        swal({
            title: "Template missing",
            text: "IOS Template is not uploaded in Step 3",
            icon: "error"
        });
        return false;
    }
    let inventory_file = document.getElementById("inventory_file").files[0];
    if (inventory_file === undefined) {
        swal({
            title: "Inventory missing",
            text: "IOS Inventory is not uploaded in Step 5",
            icon: "error"
        });
        return false;
    }
    $(".progress_bar").css("display", "block");
    $("#output").val("");
    let ios_form = document.createElement("form");
    ios_form.method = "POST";
    ios_form.action = "/ios";
    ios_form.setAttribute("enctype", "multipart/form-data");

    ios_form.appendChild(document.getElementById("menu_option"));
    ios_form.appendChild(document.getElementById("deployment_file"));
    ios_form.appendChild(document.getElementById("inventory_file"));
    document.body.appendChild(ios_form);
    ios_form.submit();
}

function sidebar_open() {
    $("#mySidebar").css("display", "block");
    $(".nav").css("display", "none");
    $(".sub_nav").css("display", "none");
    $("#heading").css("left", "330px");
    $("#heading").css("top", "40px");
    $("#output").css("width", "90%");
}

function sidebar_close() {
    $("#mySidebar").css("display", "none");
    $(".nav").css("display", "block");
    $(".sub_nav").css("display", "block");
    $("#heading").css("left", "60px");
    $("#heading").css("top", "120px");
    $("#output").css("width", "100%");
}

$("#download_result").click(function () {
  // create `a` element
  $("<a />", {
      // if supported , set name of file
      download: "Result.txt",
      // set `href` to `objectURL` of `Blob` of `textarea` value
      href: URL.createObjectURL(
        new Blob([$("#output").val()], {
          type: "text/plain"
        }))
    })
    // append `a` element to `body`
    // call `click` on `DOM` element `a`
    .appendTo("body")[0].click();
    // remove appended `a` element after "Save File" dialog,
    // `window` regains `focus`
    $(window).one("focus", function() {
      $("a").last().remove()
    })
});

$("#output").on("DOMNodeInserted", function() {
    $(".progress_bar").css("display", "none");
});
