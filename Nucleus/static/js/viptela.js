function selected_option(option) {
    let menu_options = {
        "1.1": "AAA",
        "1.2": "BFD",
        "1.3": "NTP",
        "1.4": "OMP",
        "1.5": "Security",
        "1.6": "System",
        "1.7": "VPN",
        "1.8": "VPN Interface",
        "1.9": "Banner",
        "1.10": "Logging",
        "1.11": "OSPF",
        "1.12": "SNMP",
        "2.1": "Device Template",
        "3.1": "Delete Feature Template",
        "3.2": "Delete Device Template"
    };
    let menu_option = document.getElementById("menu_option");
    menu_option.value = menu_option.title = menu_options[option];
    const x = document.getElementById("sdwan_menu");
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

function get_template_name() {
    document.getElementById("template_name"
    ).innerHTML = "Template Name: &nbsp;&nbsp;" + document.getElementById("uploaded_file").files[0].name
}


function execute_vmanage() {
    let menu_option = document.getElementById("menu_option").value;
    if (menu_option === "") {
        swal({
            title: "Menu option missing",
            text: "Viptela SD-WAN Menu is not selected in Step 1",
            icon: "error"
        });
        return false;
    }
    let uploaded_file = document.getElementById("uploaded_file").files[0];
    if (uploaded_file === undefined) {
        swal({
            title: "Template missing",
            text: "Viptela SD-WAN Template is not uploaded in Step 3",
            icon: "error"
        });
        return false;
    }
    let ip_format = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    let host_ip = document.getElementById("host_ip").value;
    if (host_ip === "") {
        swal({
            title: "IP Address missing",
            text: "vManage Host IP Address in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    else if (!host_ip.match(ip_format)){
        swal({
            title: "Invalid IP Address",
            text: document.getElementById("host_ip").value,
            icon: "error"
        });
        return false;
    }
    let vmanage_username = document.getElementById("vmanage_username").value;
    if (vmanage_username === "") {
        swal({
            title: "Credentials missing",
            text: "vManage username in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    let vmanage_password = document.getElementById("vmanage_password").value;
    if (vmanage_password === "") {
        swal({
            title: "Credentials missing",
            text: "vManage password in Step 4 is missing",
            icon: "error"
        });
        return false;
    }

    $(".progress_bar").css("display", "block");
    $("#output").val("");
    let vmanage_form = document.createElement("form");
    vmanage_form.method = "POST";
    vmanage_form.action = "/viptela";
    vmanage_form.setAttribute("enctype", "multipart/form-data");
    vmanage_form.appendChild(document.getElementById("menu_option"));
    vmanage_form.appendChild(document.getElementById("host_ip"));
    vmanage_form.appendChild(document.getElementById("vmanage_username"));
    vmanage_form.appendChild(document.getElementById("vmanage_password"));
    vmanage_form.appendChild(document.getElementById("uploaded_file"));
    document.body.appendChild(vmanage_form);
    vmanage_form.submit();
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
