function selected_option(option) {
    let menu_options = {
        "1.1": "DNS Server Configuration",
        "1.2": "NTP Configuration",
        "1.3": "Syslog Configuration",
        "2.1": "Trunk Interface Configuration",
        "2.2": "VLAN Configuration",
        "2.3": "Self-IP Configuration",
        "3.1": "Configure LTM Virtual Server and Pool Member",
        "3.2": "Configure LTM Pool and Pool Member",
        "3.3": "Update LTM Virtual Server",
        "3.4": "Update LTM Pool Member(s)"
    };
    let menu_option = document.getElementById("menu_option");
    menu_option.value = menu_option.title = menu_options[option];
    const x = document.getElementById("f5_menu");
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

function execute_f5() {
    let menu_option = document.getElementById("menu_option").value;
    if (menu_option === "") {
        swal({
            title: "Menu option missing",
            text: "F5 Menu is not selected in Step 1",
            icon: "error"
        });
        return false;
    }
    let uploaded_file = document.getElementById("uploaded_file").files[0];
    if (uploaded_file === undefined) {
        swal({
            title: "Template missing",
            text: "F5 Template is not uploaded in Step 3",
            icon: "error"
        });
        return false;
    }
    let f5_username = document.getElementById("f5_username").value;
    if (f5_username === "") {
        swal({
            title: "Credentials missing",
            text: "F5 username in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    let f5_password = document.getElementById("f5_password").value;
    if (f5_password === "") {
        swal({
            title: "Credentials missing",
            text: "F5 password in Step 4 is missing",
            icon: "error"
        });
        return false;
    }
    $(".progress_bar").css("display", "block");
    $("#output").val("");
    let f5_form = document.createElement("form");
    f5_form.method = "POST";
    f5_form.action = "/f5";
    f5_form.setAttribute("enctype", "multipart/form-data");

    f5_form.appendChild(document.getElementById("menu_option"));
    f5_form.appendChild(document.getElementById("f5_username"));
    f5_form.appendChild(document.getElementById("f5_password"));
    f5_form.appendChild(document.getElementById("uploaded_file"));
    document.body.appendChild(f5_form);
    f5_form.submit();
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
