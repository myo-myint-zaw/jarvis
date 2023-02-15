function selected_option(option) {
    let menu_options = {
        "1.1": "Perform Node Registration",
        "1.2": "Configure OOB/INB IP Address Pool",
        "1.3": "Configure Node Management Addresses",
        "2.1": "Configure Switch Policies",
        "2.2": "Configure Switch vPC Pairs",
        "2.3": "Configure VPool, Domains, AEP",
//        "2.4": "Configure Layer-2 Policies (LACP/LLDP/L2 Interface)",
        "2.4": "Configure Layer-2 Policies (LACP/LLDP/CDP)",
        "2.5": "Configure Interface Policy Group",
        "2.6": "Activate Switch Ports with Policy Group",
        "3.1": "Configure Tenants",
        "3.2": "Configure VRFs for Tenants",
        "3.3": "Configure BDs for Tenants",
        "3.4": "Configure Application Profiles for Tenants",
        "3.5": "Configure EPGs & Contracts for Tenants",
        "3.6": "Deploy Interfaces in EPG"
    };
    let menu_option = document.getElementById("menu_option");
    menu_option.value = menu_option.title = menu_options[option];
    const x = document.getElementById("cisco_menu");
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


function execute_aci() {
    let menu_option = document.getElementById("menu_option").value;
    if (menu_option === "") {
        swal({
            title: "Menu option missing",
            text: "ACI Menu is not selected in Step 1",
            icon: "error"
        });
        return false;
    }
    let uploaded_file = document.getElementById("uploaded_file").files[0];
    if (uploaded_file === undefined) {
        swal({
            title: "Template missing",
            text: "ACI Template is not uploaded in Step 3",
            icon: "error"
        });
        return false;
    }
    let ip_format = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/;
    let host_ip = document.getElementById("host_ip").value;
    if (host_ip === "") {
        swal({
            title: "IP Address missing",
            text: "ACI Host IP Address in Step 4 is missing",
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
    let aci_username = document.getElementById("aci_username").value;
    if (aci_username === "") {
        swal({
            title: "Credentials missing",
            text: "ACI username in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    let aci_password = document.getElementById("aci_password").value;
    if (aci_password === "") {
        swal({
            title: "Credentials missing",
            text: "ACI password in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    if (ajax_aci_login() !== true)
        return false;
    $(".progress_bar").css("display", "block");
    $("#output").val("");
    let aci_form = document.createElement("form");
    aci_form.method = "POST";
    aci_form.action = "/aci";
    aci_form.setAttribute("enctype", "multipart/form-data");

    aci_form.appendChild(document.getElementById("menu_option"));
    aci_form.appendChild(document.getElementById("host_ip"));
    aci_form.appendChild(document.getElementById("aci_username"));
    aci_form.appendChild(document.getElementById("aci_password"));
    aci_form.appendChild(document.getElementById("uploaded_file"));
    document.body.appendChild(aci_form);
    aci_form.submit();
}

function ajax_aci_login() {
    let ajax_response = false;
    $.ajax({
        type: "POST",
        url: "/aci_login",
        contentType: 'application/json',
        data: JSON.stringify({
            host_ip: document.querySelector("#host_ip").value,
            username: document.querySelector("#aci_username").value,
            password: document.querySelector("#aci_password").value
        }),
        success: function(res) {
            if (res !== "success"){
                swal({
                    title: "ACI Login failed",
                    text: "Unable to login to ACI in Step 4",
                    icon: "error"
                });
                document.querySelector("#aci_password").value = "";
            }
            else
                ajax_response = true;
        },
        error: function() {
            swal({
                title: "ACI Login failed",
                text: "Unable to login to ACI in Step 4",
                icon: "error"
            });
            document.querySelector("#aci_password").value = "";
        },
        async: false
    });
    return ajax_response;
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
