const form =
document.getElementById("loginForm");

form.addEventListener("submit", (e)=>{

    e.preventDefault();

    const role =
    document.getElementById("role").value;

    if(role === "admin"){

        window.location.href =
        "dashboard.html";

    }

    else{

        window.location.href =
        "dashboard.html";

    }

});