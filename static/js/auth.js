function sign_in() {
    let username = $("#username").val();
    let password = $("#password").val();

    if (username === "") {
        $("#help-username").text("Please input your username.");
        $("#username").focus();
        return;
    } else {
        $("#help-username").text("");
    }

    if (password === "") {
        $("#help-password").text("Please input your password.");
        $("#password").focus();
        return;
    } else {
        $("#help-password").text("");
    }

    console.log(username, password);
    $.ajax({
        type: "POST",
        url: "/sign_in",
        data: {
            username_give: username,
            password_give: password,
        },
        success: function (response) {
            if (response["result"] === "success") {
                $.cookie("nande", response["token"], { path: "/" });
                window.location.replace("/");
            } else {
                alert(response["msg"]);
            }
        },
    });
}

function sign_up(){
    let fullname = $("#fullname").val();
    let username = $("#username").val();
    let password = $("#password").val();

    if (username === "" && fullname === "") {
        $("#help-username").text("Please input your username.");
        $("#username").focus();
        return;
    } else {
        $("#help-username").text("");
    }

    if (password === "") {
        $("#help-password").text("Please input your password.");
        $("#password").focus();
        return;
    } else {
        $("#help-password").text("");
    }

    console.log(fullname, username, password);
    $.ajax({
        type: "POST",
        url: "/sign_up",
        data: {
            fullname_give: fullname,
            username_give: username,
            password_give: password,
        },
        success: function (response) {
            Swal.fire({
                icon: 'success',
                title: 'Sign Up Successfully!',
                text: 'Click OK to go to login page',
                willClose: () => {
                    window.location.replace('/login')
                }
          });
        },
    });
}

function sign_out() {
    Swal.fire({
        icon: 'success',
        title: 'You Logged Off',
        text: 'Click OK to go to login page',
        willClose: () => {
            $.removeCookie('nande', { path: '/' });
            window.location.replace('/login')
        }
  });
}